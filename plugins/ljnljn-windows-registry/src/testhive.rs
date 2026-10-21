//! 合成 hive 构造器——**仅供单元测试使用**(`#[cfg(test)]`)。
//!
//! 按 REGF / hbin / nk / vk / lf 规范在内存里拼出最小合法 hive,用于:
//!   * 往返验证:已知口令 → MD4(UTF-16LE) → bootkey → RC4+AES 加密 → 解析 → 解密比对
//!   * 边界与损坏场景:截断、偏移越界、置换顺序错误、缺少 F/V 值等
//!
//! 构造数据全部由测试参数生成,与任何真实案件无关。

#![cfg(test)]

use crate::crypto::{aes_cbc_encrypt_zero_iv, md4, rc4::rc4};
use crate::sam_parse::PERMUTATION;

const HBIN_START: usize = 0x20;

/// hive 里的一个键:名称 + 类名 + 值 + 子键
pub struct KeySpec {
    pub name: String,
    pub class: Option<Vec<u8>>,
    pub values: Vec<(String, u32, Vec<u8>)>,
    pub children: Vec<KeySpec>,
}

impl KeySpec {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            class: None,
            values: Vec::new(),
            children: Vec::new(),
        }
    }

    pub fn child(mut self, child: KeySpec) -> Self {
        self.children.push(child);
        self
    }

    pub fn class(mut self, class: Vec<u8>) -> Self {
        self.class = Some(class);
        self
    }

    pub fn value(mut self, name: &str, kind: u32, data: Vec<u8>) -> Self {
        self.values.push((name.to_string(), kind, data));
        self
    }
}

fn cell_size(payload: usize) -> usize {
    (payload + 8).div_ceil(8) * 8
}

#[derive(Clone, Copy, Debug)]
struct CellSpec {
    offset: usize,
    length: usize,
}

struct Builder {
    hbins: Vec<u8>,
    next: usize,
}

impl Builder {
    fn new() -> Self {
        Self {
            hbins: Vec::new(),
            next: HBIN_START,
        }
    }

    fn allocate(&mut self, payload: usize) -> CellSpec {
        let length = cell_size(payload);
        let offset = self.next;
        self.hbins.resize(offset + length, 0);
        self.next = offset + length;
        CellSpec { offset, length }
    }

    fn write_cell(&mut self, cell: CellSpec, payload: &[u8]) {
        let length = cell.length as i32;
        self.hbins[cell.offset..cell.offset + 4].copy_from_slice(&length.to_le_bytes());
        self.hbins[cell.offset + 4..cell.offset + 4 + payload.len()].copy_from_slice(payload);
        let tail = cell.offset + cell.length - 4;
        self.hbins[tail..tail + 4].copy_from_slice(&length.to_le_bytes());
    }

    fn build_key(&mut self, spec: &KeySpec) -> u64 {
        let name_bytes = utf16_bytes(&spec.name);
        let cell = self.allocate(0x4C + name_bytes.len());
        let class_cell = match spec.class.as_ref().filter(|class| !class.is_empty()) {
            Some(class) => {
                let inner = self.allocate(class.len());
                self.write_cell(inner, class);
                Some((inner, class.len()))
            }
            None => None,
        };
        let sub_offsets: Vec<u32> = spec
            .children
            .iter()
            .map(|child| {
                let cell = self.build_key(child);
                cell as u32
            })
            .collect();
        let sub_list = if sub_offsets.is_empty() {
            None
        } else {
            let mut data = vec![0u8; 4 + sub_offsets.len() * 4];
            data[0..2].copy_from_slice(&0x6C66u16.to_le_bytes()); // "lf"
            data[2..4].copy_from_slice(&(sub_offsets.len() as u16).to_le_bytes());
            for (index, offset) in sub_offsets.iter().enumerate() {
                data[4 + index * 4..8 + index * 4].copy_from_slice(&offset.to_le_bytes());
            }
            let list = self.allocate(data.len());
            self.write_cell(list, &data);
            Some(list)
        };
        let mut value_offsets = Vec::new();
        for (name, kind, payload) in &spec.values {
            let value_name = utf16_bytes(name);
            let inline = payload.len() <= 4;
            let data_cell = if inline || payload.is_empty() {
                None
            } else {
                let inner = self.allocate(payload.len());
                self.write_cell(inner, payload);
                Some(inner)
            };
            let inline_extra = if inline { payload.len() } else { 0 };
            let value_cell = self.allocate(0x14 + value_name.len() + inline_extra);
            let mut cell_payload = vec![0u8; 0x14 + value_name.len() + inline_extra];
            cell_payload[0..2].copy_from_slice(&0x6B76u16.to_le_bytes()); // "vk"
            cell_payload[2..4].copy_from_slice(&(value_name.len() as u16).to_le_bytes());
            let stored_len = if inline {
                (payload.len() as u32) | 0x8000_0000
            } else {
                payload.len() as u32
            };
            cell_payload[4..8].copy_from_slice(&stored_len.to_le_bytes());
            match data_cell {
                Some(inner) => {
                    cell_payload[8..0xC].copy_from_slice(&(inner.offset as u32).to_le_bytes())
                }
                None => cell_payload[8..0xC].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()),
            }
            cell_payload[0xC..0x10].copy_from_slice(&kind.to_le_bytes());
            cell_payload[0x10..0x12].copy_from_slice(&1u16.to_le_bytes());
            cell_payload[0x14..0x14 + value_name.len()].copy_from_slice(&value_name);
            if inline && !payload.is_empty() {
                let at = 0x14 + value_name.len();
                cell_payload[at..at + payload.len()].copy_from_slice(payload);
            }
            self.write_cell(value_cell, &cell_payload);
            value_offsets.push(value_cell.offset as u32);
        }
        let value_list = if value_offsets.is_empty() {
            None
        } else {
            let mut data = Vec::new();
            for offset in &value_offsets {
                data.extend_from_slice(&offset.to_le_bytes());
            }
            let list = self.allocate(data.len());
            self.write_cell(list, &data);
            Some(list)
        };

        let mut payload = vec![0u8; 0x4C + name_bytes.len()];
        payload[0..2].copy_from_slice(&0x6B6Eu16.to_le_bytes()); // "nk"
        payload[2..4].copy_from_slice(&0x2C20u16.to_le_bytes());
        if let Some(list) = &sub_list {
            payload[0x14..0x18].copy_from_slice(&(sub_offsets.len() as u32).to_le_bytes());
            payload[0x1C..0x20].copy_from_slice(&(list.offset as u32).to_le_bytes());
        }
        if let Some(list) = &value_list {
            payload[0x24..0x28].copy_from_slice(&(value_offsets.len() as u32).to_le_bytes());
            payload[0x28..0x2C].copy_from_slice(&(list.offset as u32).to_le_bytes());
        }
        payload[0x38..0x3C].copy_from_slice(&64u32.to_le_bytes());
        payload[0x3C..0x40].copy_from_slice(&1024u32.to_le_bytes());
        payload[0x48..0x4A].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        match class_cell {
            Some((offset, len)) => {
                let offset = offset.offset;
                payload[0x2C..0x30].copy_from_slice(&(offset as u32).to_le_bytes());
                payload[0x4A..0x4C].copy_from_slice(&(len as u16).to_le_bytes());
            }
            None => payload[0x2C..0x30].copy_from_slice(&0xFFFF_FFFFu32.to_le_bytes()),
        }
        payload[0x4C..].copy_from_slice(&name_bytes);
        self.write_cell(cell, &payload);
        cell.offset as u64
    }

    fn finish(self) -> Vec<u8> {
        let hbin_size = ((self.hbins.len() + 0xFFF) & !0xFFF).max(0x1000);
        let mut hbins = self.hbins;
        hbins.resize(hbin_size, 0);
        let free_start = self.next;
        if free_start + 8 <= hbin_size {
            let free_len = (hbin_size - free_start) as i32;
            hbins[free_start..free_start + 4].copy_from_slice(&free_len.to_le_bytes());
            hbins[hbin_size - 4..hbin_size].copy_from_slice(&free_len.to_le_bytes());
        }
        hbins[0..4].copy_from_slice(b"hbin");
        // hbin 的“相对偏移”字段存放该 hbin 的绝对文件偏移(首个 hbin 为 0x1000)
        hbins[4..8].copy_from_slice(&(0x1000u32).to_le_bytes());
        hbins[8..0xC].copy_from_slice(&(hbin_size as u32).to_le_bytes());
        let mut file = vec![0u8; 0x1000];
        file[0..4].copy_from_slice(b"regf");
        file[4..8].copy_from_slice(&1u32.to_le_bytes());
        file[8..0xC].copy_from_slice(&1u32.to_le_bytes());
        file[0x24..0x28].copy_from_slice(&1u32.to_le_bytes());
        file[0x28..0x2C].copy_from_slice(&5u32.to_le_bytes());
        file[0x30..0x34].copy_from_slice(&1u32.to_le_bytes());
        file[0x38..0x3C].copy_from_slice(&(hbin_size as u32).to_le_bytes());
        file.extend_from_slice(&hbins);
        file
    }
}

pub fn utf16_bytes(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in text.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out
}

/// 用根键规格构造完整 hive 字节流。
pub fn build_hive(root: &KeySpec) -> Vec<u8> {
    let mut builder = Builder::new();
    let root_offset = builder.build_key(root);
    let mut bytes = builder.finish();
    bytes[0x34..0x38].copy_from_slice(&(root_offset as u32).to_le_bytes());
    bytes
}

// ---------------------------------------------------------------------------
// bootkey / 类名
// ---------------------------------------------------------------------------

/// 由 16 字节 bootkey 反算 JD/Skew1/GBG/Data 四个类名(每个 8 个十六进制字符,
/// 对应 4 字节;共 32 个十六进制字符 = 16 字节置换前数据)。
pub fn lsa_classes(bootkey: &[u8; 16]) -> [String; 4] {
    let mut permuted = [0u8; 16];
    for (index, target) in PERMUTATION.iter().enumerate() {
        permuted[*target] = bootkey[index];
    }
    let mut out: [String; 4] = Default::default();
    for (group, chunk) in permuted.chunks(4).enumerate() {
        let mut class = String::new();
        for byte in chunk {
            class.push_str(&format!("{byte:02X}"));
        }
        out[group] = class;
    }
    out
}

/// 由 SYSTEM Lsa 的四个类名派生 bootkey(测试侧独立实现,供交叉断言)。
pub fn bootkey_from_classes(classes: &[String; 4]) -> [u8; 16] {
    let mut permuted = Vec::new();
    for class in classes {
        for pair in 0..4 {
            let at = pair * 2;
            let byte = u8::from_str_radix(&class[at..at + 2], 16).expect("hex class");
            permuted.push(byte);
        }
    }
    assert_eq!(permuted.len(), 16);
    let mut key = [0u8; 16];
    for (index, target) in PERMUTATION.iter().enumerate() {
        key[index] = permuted[*target];
    }
    key
}

// ---------------------------------------------------------------------------
// SAM 哈希区加密(与解析器相反的独立实现)
// ---------------------------------------------------------------------------

/// FakeBootKey = MD5(SysKey) 的前 16 字节
pub fn fake_boot_key(syskey: &[u8; 16]) -> [u8; 16] {
    let digest = md4::md5(syskey);
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest);
    out
}

/// Key0 = RC4(bootkey, 16×0x00)
pub fn key0(bootkey: &[u8; 16]) -> Vec<u8> {
    rc4(bootkey, &[0u8; 16])
}

/// 用户级密钥:Key0 经 RC4(FakeBootKey, 32×0x00) 得到 32 字节,
/// 再按 RID 派生 Key1(首 16 字节)与 Key2(其余),两者异或后进行 AES-128-CBC。
pub fn per_user_keys(fake: &[u8; 16], rid: u32) -> (Vec<u8>, Vec<u8>) {
    let mut rid_bytes = [0u8; 16];
    rid_bytes[0..4].copy_from_slice(&rid.to_le_bytes());
    let key1 = rc4(fake, &rid_bytes);
    rid_bytes[0] = 2;
    let key2 = rc4(fake, &rid_bytes);
    (key1, key2)
}

/// 按解析器文档的布局加密一条用户哈希:
///   IV(16×0x00) || u32 0x10 || NT(16) || LM(16,可为空) || MD4(NT||LM) || 零填充
/// 先 AES-128-CBC(IV 全零)加密,再用 Key1/Key2 逐块异或。
pub fn encrypt_user_hash(
    rid: u32,
    nt: &[u8; 16],
    lm: &[u8],
    aes_key: &[u8],
    fake: &[u8; 16],
) -> Vec<u8> {
    let mut plain = Vec::new();
    plain.extend_from_slice(&[0u8; 16]); // IV
    plain.extend_from_slice(&0x10u32.to_le_bytes());
    plain.extend_from_slice(nt);
    plain.extend_from_slice(lm);
    plain.extend_from_slice(&md4::md4(&[nt.as_slice(), lm].concat()));
    while plain.len() % 16 != 0 {
        plain.push(0);
    }
    let encrypted = aes_cbc_encrypt_zero_iv(aes_key, &plain).expect("AES-128-CBC");
    let (key1, key2) = per_user_keys(fake, rid);
    let mut out = Vec::with_capacity(encrypted.len());
    out.extend_from_slice(&rc4(&key1, &encrypted[..encrypted.len().min(16)]));
    out.extend_from_slice(&rc4(&key2, &encrypted[16..]));
    out
}

// ---------------------------------------------------------------------------
// SYSTEM / SAM 取值构造
// ---------------------------------------------------------------------------

/// 构造 SYSTEM hive 的完整根键:`CurrentControlSet\Control\Lsa\{JD,Skew1,GBG,Data}`,
/// 每个子键的类名是 8 个十六进制字符。
pub fn system_root(classes: &[String; 4]) -> KeySpec {
    let mut lsa = KeySpec::new("Lsa");
    for (index, name) in ["JD", "Skew1", "GBG", "Data"].iter().enumerate() {
        lsa = lsa.child(KeySpec::new(name).class(classes[index].as_bytes().to_vec()));
    }
    KeySpec::new("SYSTEM").child(
        KeySpec::new("CurrentControlSet")
            .child(KeySpec::new("Control").child(lsa)),
    )
}

/// F 值:用户名在偏移 0x60 处(0x3C 相对偏移 = 0x60,0x40 为 u16 长度,0x42 为登录次数)。
pub fn user_f(name: &str, rid: u32, login_count: u16, last_login: u64) -> Vec<u8> {
    let name_bytes = utf16_bytes(name);
    let mut out = vec![0u8; 0x60 + name_bytes.len()];
    out[0x08..0x10].copy_from_slice(&last_login.to_le_bytes());
    out[0x3C..0x40].copy_from_slice(&0x60u32.to_le_bytes());
    out[0x40..0x42].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    out[0x30..0x34].copy_from_slice(&rid.to_le_bytes());
    out[0x42..0x44].copy_from_slice(&login_count.to_le_bytes());
    out[0x60..].copy_from_slice(&name_bytes);
    out
}

/// `Users\<rid>` 子键:`F` 与 `V` 两个值。
pub fn user_key(key_name: &str, f: Vec<u8>, v: Vec<u8>) -> KeySpec {
    KeySpec::new(key_name)
        .value("F", 3, f)
        .value("V", 3, v)
}

/// 只有 F、没有 V 的用户子键(场景 5)。
pub fn user_key_without_v(key_name: &str, f: Vec<u8>) -> KeySpec {
    KeySpec::new(key_name).value("F", 3, f)
}

/// 只有 V、没有 F 的用户子键(场景 5)。
pub fn user_key_without_f(key_name: &str, v: Vec<u8>) -> KeySpec {
    KeySpec::new(key_name).value("V", 3, v)
}

/// 构造 `SAM\Domains\Account\{F,Users\...}` 根键。
pub fn sam_root(f_value: Option<Vec<u8>>, users: Vec<KeySpec>) -> KeySpec {
    let mut account = KeySpec::new("Account");
    if let Some(f) = f_value {
        account = account.value("F", 3, f);
    }
    let mut users_key = KeySpec::new("Users");
    for user in users {
        users_key = users_key.child(user);
    }
    account = account.child(users_key);
    KeySpec::new("SAM").child(KeySpec::new("Domains").child(account))
}

// ---------------------------------------------------------------------------
// 高层场景样例
// ---------------------------------------------------------------------------

/// 一个测试场景所需的全部材料。
pub struct Sample {
    pub system_bytes: Vec<u8>,
    pub sam_bytes: Vec<u8>,
    pub bootkey: [u8; 16],
    pub syskey: [u8; 16],
    pub classes: [String; 4],
    pub fake: [u8; 16],
    pub aes_key: Vec<u8>,
}

/// 用给定口令/占位构造“一个普通账号”的最小样例。
pub fn sample_with_account(
    account_name: &str,
    rid: u32,
    nt_hash: &[u8; 16],
    lm_hash: &[u8],
) -> Sample {
    let syskey: [u8; 16] = [
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE,
        0xFF, 0x00,
    ];
    // 独立选择 bootkey(与 hashed bootkey 不同的 16 字节)
    let bootkey: [u8; 16] = [
        0x05, 0x11, 0x27, 0x33, 0x49, 0x55, 0x61, 0x77, 0x83, 0x95, 0xA7, 0xB9, 0xCB, 0xDD,
        0xEF, 0x01,
    ];
    let classes = lsa_classes(&bootkey);
    let fake = fake_boot_key(&syskey);
    let aes_key = key0(&bootkey);
    let cipher = encrypt_user_hash(rid, nt_hash, lm_hash, &aes_key, &fake);
    Sample {
        system_bytes: build_hive(&system_root(&classes)),
        sam_bytes: build_hive(&sam_root(
            Some(f_value_bytes(&syskey)),
            vec![user_key(
                &format!("{rid:08X}"),
                user_f(account_name, rid, 7, 132_000_000_000_000_000),
                v_value(&cipher, lm_hash.len()),
            )],
        )),
        bootkey,
        syskey,
        classes,
        fake,
        aes_key,
    }
}

/// `Domains\Account\F`:0x08 起放 SysKey(FakeBootKey 来源)。
pub fn f_value_bytes(syskey: &[u8; 16]) -> Vec<u8> {
    let mut out = vec![0u8; 0x50];
    out[0x08..0x18].copy_from_slice(syskey);
    out
}

/// V 值:哈希区结构头(0x9C)指向 16 字节对齐处的密文。
pub fn v_value(cipher: &[u8], lm_len: usize) -> Vec<u8> {
    let start = ((0x9C + 8 + 15) / 16) * 16;
    let mut out = vec![0u8; start + cipher.len()];
    out[0x9C..0xA0].copy_from_slice(&(start as u32).to_le_bytes());
    out[0xA0..0xA4].copy_from_slice(&16u32.to_le_bytes());
    out[0xA4..0xA8].copy_from_slice(&((start + 16) as u32).to_le_bytes());
    out[0xA8..0xAC].copy_from_slice(&(lm_len as u32).to_le_bytes());
    out[start..].copy_from_slice(cipher);
    out
}
