//! SAM 账号与哈希提取。
//!
//! 路径:`SAM\SAM\Domains\Account\Users`(根键名通常是 `SAM`)。
//! 每个子键名为 8 位十六进制 RID,内含:
//!   * `V` 值 0x9C 起的 8 个 u32:NT 相对偏移/长度、LM 相对偏移/长度。
//!     相对偏移以 V 值数据起点为基准;密文通常从 16 字节对齐处开始。
//!     Windows 对每个长度额外 +4 覆盖校验和长度,这里按实际情况裁剪。
//!   * `F` 值:用户名偏移 0x3C(相对 F 起点)/长度 0x40,登录次数 0x42,
//!     最后登录 FILETIME 偏移 0x08,RID 偏移 0x30(与控制键名交叉校验)。
//!
//! 哈希区明文布局(以结构头给出的哈希区起点为 0):
//!   0x00  16 字节 IV(应为全零)
//!   0x10  u32 固定标记 0x10(= NT 哈希长度)
//!   0x14  NT 哈希 16 字节
//!   0x24  LM 哈希(结构头 lm_len 为 0 时不存在,否则 16 字节)
//!   ...   MD4(NT || LM) 校验和 16 字节
//!   ...   零填充到 16 字节分组边界
//! AAD 校验 = IV 全零 + 标记字段 + MD4 校验和。校验失败一律 `decrypt_ok = false`
//! 并保留原始原因,不输出猜测的哈希值。
//!
//! 解密链:bootkey --RC4--> Key0(哈希区 AES-128 密钥);
//!          AES(Key0, RC4(FakeBootKey, 32×0x00)) --RC4(FakeBootKey)--> Key1/Key2,
//!          前 16 字节用 Key1、其余用 Key2 异或后再 AES-128-CBC(IV 全零)解密。

use crate::bootkey::{faux_secret, BootKey};
use crate::crypto::{aes_cbc_decrypt_zero_iv, md4::md4, rc4::rc4};
use crate::regf::{Hive, RegfResult};
use crate::sid::{compose_sid, Sid};

/// bootkey 置换表(公开格式常量)
pub const PERMUTATION: [usize; 16] = [
    8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7,
];

/// `SAM\Domains\Account\Users` 路径(根键名通常是 `SAM`)
pub const USERS_PATH: [&str; 4] = ["SAM", "Domains", "Account", "Users"];
/// `SAM\Domains\Account` 路径(F 值所在)
pub const ACCOUNT_PATH: [&str; 3] = ["SAM", "Domains", "Account"];

/// 哈希区明文里的 IV 长度
pub const HASH_IV_LEN: usize = 16;
/// 哈希区明文里的 NT 长度标记
pub const HASH_LEN_MARKER: usize = 0x10;

/// NT/LM 哈希状态
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HashState {
    /// 成功得到小写十六进制
    Present(String),
    /// 明确不可得;字符串是原因,绝不用猜测值填充
    Unavailable(String),
}

impl HashState {
    pub fn hex(&self) -> Option<&str> {
        match self {
            Self::Present(hex) => Some(hex.as_str()),
            Self::Unavailable(_) => None,
        }
    }

    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Present(_) => None,
            Self::Unavailable(reason) => Some(reason.as_str()),
        }
    }
}

/// 单个账号的提取结果(输出字段的第一层)
#[derive(Clone, Debug, PartialEq)]
pub struct AccountRecord {
    pub account_name: String,
    /// 域名前缀 + RID 拼出的完整 SID（Names 默认值可解析时）
    pub account_sid: Option<String>,
    pub rid: u32,
    /// SAM 中的 8 位十六进制子键名(保持原始大小写)
    pub user_key_name: String,
    pub user_key_path: String,
    pub nt_hash: HashState,
    pub lm_hash: HashState,
    /// "NT" / "LM" / "none"
    pub hash_algorithm: &'static str,
    pub login_count: Option<u16>,
    /// 原始 FILETIME(100ns,自 1601-01-01 UTC)
    pub last_login_filetime: Option<u64>,
    /// UTC ISO-8601(原始时区未知)
    pub last_login_utc: Option<String>,
    pub decrypt_ok: bool,
    pub decrypt_reason: Option<String>,
    pub nt_offset: Option<u32>,
    pub nt_len: Option<u32>,
    pub lm_offset: Option<u32>,
    pub lm_len: Option<u32>,
    pub f_rid: Option<u32>,
    pub limitations: Vec<String>,
}

/// 由 bootkey 派生出的哈希区密钥
pub struct HashKeys {
    /// RC4(bootkey, 16×0x00):哈希区 AES-128 密钥
    pub aes_key: Vec<u8>,
    pub fake_boot_key: Option<[u8; 16]>,
    pub notes: Vec<String>,
}

pub fn hash_keys(bootkey: &[u8; 16], fake: Option<[u8; 16]>) -> HashKeys {
    let mut notes = Vec::new();
    if fake.is_none() {
        notes.push(
            "FakeBootKey 不可用:仍可识别空密码全零/占位编码,但无法做 AES 解密(decryptOk=false)"
                .to_string(),
        );
    }
    HashKeys {
        aes_key: rc4(bootkey, &[0u8; 16]),
        fake_boot_key: fake,
        notes,
    }
}

/// 尝试从 SAM hive 的 `Domains\Account\F` 读取 FakeBootKey(可选交叉校验)。
pub fn try_fake_boot_key(hive: &Hive) -> (Option<[u8; 16]>, Vec<String>) {
    match faux_secret(hive) {
        Ok(fake) => (Some(fake), Vec::new()),
        Err(error) => (
            None,
            vec![format!(
                "FakeBootKey(Account\\F 值)不可用({}),哈希区 AES 密钥无法派生,不阻断主流程",
                error.describe()
            )],
        ),
    }
}

fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    data.get(offset..offset + 4)
        .map(|slice| u32::from_le_bytes(slice.try_into().unwrap_or([0; 4])))
}

fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
    data.get(offset..offset + 2)
        .map(|slice| u16::from_le_bytes(slice.try_into().unwrap_or([0; 2])))
}

/// FILETIME(100ns)→ UTC ISO-8601。0 或越界返回 `None`。
pub fn filetime_to_utc(filetime: u64) -> Option<String> {
    if filetime == 0 || filetime > 2_650_467_743_999_999_999 {
        return None;
    }
    let unix_seconds = (filetime / 10_000_000) as i64 - 11_644_473_600;
    let sub = filetime % 10_000_000;
    let days = unix_seconds.div_euclid(86_400);
    let seconds_of_day = unix_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let (hour, minute, second) = (
        seconds_of_day / 3600,
        (seconds_of_day % 3600) / 60,
        seconds_of_day % 60,
    );
    let mut out = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}");
    if sub != 0 {
        out.push_str(&format!(".{sub:07}"));
    }
    out.push('Z');
    Some(out)
}

/// Howard Hinnant civil_from_days(1970-01-01 = 0)
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// F 值解析结果
#[derive(Clone, Debug, PartialEq)]
pub struct UserF {
    pub name: String,
    pub rid: u32,
    pub login_count: u16,
    pub last_login: u64,
}

pub fn parse_f(data: &[u8]) -> Result<UserF, String> {
    if data.len() < 0x4C {
        return Err(format!("F 值长度 0x{:X} 小于键头 0x4C", data.len()));
    }
    let rid = read_u32(data, 0x30).ok_or("F 值 RID(0x30)越界")?;
    let name_rel = read_u32(data, 0x3C).ok_or("F 值用户名偏移(0x3C)越界")? as usize;
    let name_len = read_u16(data, 0x40).ok_or("F 值用户名长度(0x40)越界")? as usize;
    let name = if name_len == 0 {
        String::new()
    } else {
        let end = name_rel
            .checked_add(name_len)
            .filter(|end| *end <= data.len())
            .ok_or_else(|| {
                format!(
                    "F 值用户名区域 [0x{name_rel:X}, +0x{name_len:X}) 越过 F 值长度 0x{:X}",
                    data.len()
                )
            })?;
        let raw = &data[name_rel..end];
        if raw.len() % 2 != 0 {
            return Err("F 值用户名长度为奇数,无法按 UTF-16LE 解码".to_string());
        }
        let units: Vec<u16> = raw
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units)
            .map_err(|error| format!("F 值用户名 UTF-16LE 解码失败: {error}"))?
    };
    let login_count = read_u16(data, 0x42).ok_or("F 值登录次数(0x42)越界")?;
    let last_login = data
        .get(0x08..0x10)
        .map(|slice| u64::from_le_bytes(slice.try_into().unwrap_or([0; 8])))
        .ok_or("F 值最后登录时间(0x08)越界")?;
    Ok(UserF {
        name,
        rid,
        login_count,
        last_login,
    })
}

/// V 值 0x9C 处的哈希区结构头
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HashHeader {
    pub nt_rel: u32,
    pub nt_len: u32,
    pub lm_rel: u32,
    pub lm_len: u32,
}

impl HashHeader {
    pub fn parse(data: &[u8]) -> Result<Self, String> {
        if data.len() < 0x9C + 8 {
            return Err(format!(
                "V 值长度 0x{:X} 小于哈希区结构头的末尾位置 0xA4",
                data.len()
            ));
        }
        Ok(Self {
            nt_rel: read_u32(data, 0x9C).unwrap_or(0),
            nt_len: read_u32(data, 0xA0).unwrap_or(0),
            lm_rel: read_u32(data, 0xA4).unwrap_or(0),
            lm_len: read_u32(data, 0xA8).unwrap_or(0),
        })
    }
}

fn is_zero(data: &[u8]) -> bool {
    data.iter().all(|byte| *byte == 0)
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// 是否 8 位十六进制(用户子键命名规则)
pub fn is_rid_key(name: &str) -> bool {
    name.len() == 8 && name.chars().all(|character| character.is_ascii_hexdigit())
}

fn unavailable_everywhere(record: &mut AccountRecord, reason: String, code: &str) {
    record.nt_hash = HashState::Unavailable(reason.clone());
    record.lm_hash = HashState::Unavailable(reason.clone());
    record.decrypt_reason = Some(code.to_string());
    record.limitations.push(reason);
}

/// 解析并解密单个用户键。
pub fn extract_user(
    hive: &Hive,
    user_key_cell: u64,
    key_name: &str,
    keys: &HashKeys,
) -> Result<AccountRecord, String> {
    let values = hive
        .values(user_key_cell)
        .map_err(|error| format!("读取用户键值失败: {}", error.describe()))?;
    let f_value = values.iter().find(|value| value.name == "F");
    let v_value = values.iter().find(|value| value.name == "V");

    let mut limitations = Vec::new();
    let mut f_parsed: Option<UserF> = None;
    if let Some(value) = f_value {
        let data = hive
            .value_data(value)
            .map_err(|error| format!("读取 F 值失败: {}", error.describe()))?;
        match parse_f(&data) {
            Ok(parsed) => f_parsed = Some(parsed),
            Err(reason) => limitations.push(format!("F 值解析失败: {reason}")),
        }
    } else {
        limitations.push("缺少 F 值:用户名/登录次数/最后登录不可读".to_string());
    }
    let name_rid = u32::from_str_radix(key_name, 16).ok();
    if let (Some(parsed), Some(from_name)) = (&f_parsed, name_rid) {
        if parsed.rid != 0 && parsed.rid != from_name {
            limitations.push(format!(
                "控制键名 {key_name} 与 F 值 RID {} 不一致,以 F 值为准",
                parsed.rid
            ));
        }
    }
    let rid = f_parsed
        .as_ref()
        .map(|parsed| parsed.rid)
        .filter(|rid| *rid != 0)
        .or(name_rid)
        .ok_or_else(|| format!("无法从键名 {key_name} 或 F 值确定 RID"))?;
    let account_name = f_parsed
        .as_ref()
        .map(|parsed| parsed.name.clone())
        .unwrap_or_else(|| format!("(F值不可读:{key_name})"));

    let mut record = AccountRecord {
        account_name,
        account_sid: None,
        rid,
        user_key_name: key_name.to_string(),
        user_key_path: format!("{}\\{}", USERS_PATH.join("\\"), key_name),
        nt_hash: HashState::Unavailable("尚未读取".to_string()),
        lm_hash: HashState::Unavailable("尚未读取".to_string()),
        hash_algorithm: "none",
        login_count: f_parsed.as_ref().map(|parsed| parsed.login_count),
        last_login_filetime: f_parsed.as_ref().map(|parsed| parsed.last_login),
        last_login_utc: f_parsed
            .as_ref()
            .and_then(|parsed| filetime_to_utc(parsed.last_login)),
        decrypt_ok: false,
        decrypt_reason: None,
        nt_offset: None,
        nt_len: None,
        lm_offset: None,
        lm_len: None,
        f_rid: f_parsed.as_ref().map(|parsed| parsed.rid),
        limitations,
    };

    let Some(v_value) = v_value else {
        unavailable_everywhere(
            &mut record,
            "缺少 V 值,无法定位哈希区".to_string(),
            "missing V value",
        );
        return Ok(record);
    };
    let v_data = hive
        .value_data(v_value)
        .map_err(|error| format!("读取 V 值失败: {}", error.describe()))?;
    let header = match HashHeader::parse(&v_data) {
        Ok(header) => header,
        Err(reason) => {
            unavailable_everywhere(&mut record, reason, "missing hash structure header");
            return Ok(record);
        }
    };
    record.nt_offset = Some(header.nt_rel);
    record.nt_len = Some(header.nt_len);
    record.lm_offset = Some(header.lm_rel);
    record.lm_len = Some(header.lm_len);

    let nt_start = header.nt_rel as usize;
    let nt_len = header.nt_len as usize;
    let nt_end = nt_start.saturating_add(nt_len);
    if nt_start > v_data.len() || nt_end > v_data.len() {
        unavailable_everywhere(
            &mut record,
            format!(
                "NT 哈希区域 [0x{nt_start:X}, 0x{nt_end:X}) 越过 V 值长度 0x{:X}",
                v_data.len()
            ),
            "NT hash area out of range",
        );
        return Ok(record);
    }
    let nt_raw = &v_data[nt_start..nt_end];

    // 空密码 / 禁用账号:全零占位,如实标注 unavailable,不猜测
    if is_zero(nt_raw) {
        record.nt_hash = HashState::Unavailable(
            "空密码/禁用账号:NT 哈希为全零占位,真实哈希不可得".to_string(),
        );
        record.lm_hash =
            HashState::Unavailable("空密码/禁用账号:LM 哈希同样为全零占位".to_string());
        record.decrypt_ok = true;
        record.hash_algorithm = "none";
        record.decrypt_reason = Some("zero NT hash placeholder".to_string());
        return Ok(record);
    }

    if nt_len != 16 {
        unavailable_everywhere(
            &mut record,
            format!("NT 哈希长度 {nt_len} 非 16 字节且内容非空,按 AEAD 结构无法解密,拒绝输出猜测哈希"),
            "unexpected NT hash length",
        );
        return Ok(record);
    }
    let Some(fake) = keys.fake_boot_key else {
        unavailable_everywhere(
            &mut record,
            "FakeBootKey 不可用,无法派生 AES 密钥解密 NT 哈希".to_string(),
            "missing fake boot key",
        );
        return Ok(record);
    };

    // Key0 = RC4(bootkey, 16×0x00)，直接作为哈希区 AES-128 密钥；
    // key1/key2 只用于解除外层 RC4 混淆，不再额外派生 sub_key。
    let mut rid_bytes = [0u8; 16];
    rid_bytes[0..4].copy_from_slice(&rid.to_le_bytes());
    let key1 = rc4(&fake, &rid_bytes);
    rid_bytes[0] = 2;
    let key2 = rc4(&fake, &rid_bytes);

    // 结构头到 NT 末端之外还需容纳 LM 与校验和:统一读到 V 值末尾(有上限)
    let block_end = v_data
        .len()
        .min(nt_start + HASH_IV_LEN + 4 + 16 + 16 + 16 + 16);
    let body = &v_data[nt_start..block_end];
    if body.len() < 16 || body.len() % 16 != 0 {
        unavailable_everywhere(
            &mut record,
            format!(
                "哈希区密文长度 {} 不是 16 的整数倍或不足一个分组,无法 AES-CBC 解密",
                body.len()
            ),
            "hash block length not a multiple of 16",
        );
        return Ok(record);
    }
    match decrypt_hash_block(body, &key1, &key2, &keys.aes_key) {
        None => unavailable_everywhere(
            &mut record,
            "AES-CBC 解密失败(密钥或密文非法)".to_string(),
            "AES decryption failed",
        ),
        Some(plain) => match validate_plain(plain, header.lm_len as usize) {
            Ok((nt, lm)) => {
                record.decrypt_ok = true;
                if is_zero(&nt) {
                    // 解密成功但 NT 为全零：空密码/禁用账号的占位值，
                    // 不是可用的真实哈希。
                    record.hash_algorithm = "none";
                    record.nt_hash = HashState::Unavailable(
                        "空密码/禁用账号:NT 哈希为全零占位,真实哈希不可得".to_string(),
                    );
                    record.lm_hash = HashState::Unavailable(
                        "空密码/禁用账号:LM 哈希同样为全零占位".to_string(),
                    );
                } else {
                    record.hash_algorithm = "NT";
                    record.nt_hash = HashState::Present(hex_lower(&nt));
                    record.lm_hash = match lm {
                        None => HashState::Unavailable("结构头 LM 长度为 0(未保存)".to_string()),
                        Some(lm_bytes) if is_zero(&lm_bytes) => HashState::Unavailable(
                            "LM 哈希全零占位(Vista 之后通常不保存 LM)".to_string(),
                        ),
                        Some(lm_bytes) => HashState::Present(hex_lower(&lm_bytes)),
                    };
                }
            }
            Err(reason) => {
                let detail = format!("解密失败: {reason}");
                record.nt_hash = HashState::Unavailable(detail.clone());
                record.lm_hash = HashState::Unavailable(detail.clone());
                record.decrypt_ok = false;
                record.decrypt_reason = Some(reason.clone());
                record.limitations.push(detail);
            }
        },
    }
    Ok(record)
}

/// RC4(key1, 前 16 字节) || RC4(key2, 其余) 后 AES-128-CBC(IV 全零)解密。
fn decrypt_hash_block(body: &[u8], key1: &[u8], key2: &[u8], aes_key: &[u8]) -> Option<Vec<u8>> {
    if body.len() < 16 || body.len() % 16 != 0 {
        return None;
    }
    let first = rc4(key1, &body[..16]);
    let rest = rc4(key2, &body[16..]);
    let mut buffer = Vec::with_capacity(body.len());
    buffer.extend_from_slice(&first);
    buffer.extend_from_slice(&rest);
    aes_cbc_decrypt_zero_iv(aes_key, &buffer)
}

/// 校验 IV/AAD,返回 NT 与 LM 明文;失败返回原始原因。
pub fn validate_plain(
    plain: Vec<u8>,
    lm_len: usize,
) -> Result<([u8; 16], Option<[u8; 16]>), String> {
    if plain.len() < HASH_IV_LEN + 4 + 16 + 16 {
        return Err(format!(
            "解密结果仅 {} 字节,不足以容纳 IV/标记/NT/校验和",
            plain.len()
        ));
    }
    let (iv, body) = plain.split_at(HASH_IV_LEN);
    if !is_zero(iv) {
        return Err(format!(
            "AAD 校验失败:解密后 IV 应为全零,实际 {}",
            hex_lower(iv)
        ));
    }
    let head = u32::from_le_bytes(body[0..4].try_into().unwrap_or([0; 4])) as usize;
    if head != HASH_LEN_MARKER {
        return Err(format!(
            "AAD 校验失败:哈希区长度标记应为 0x{HASH_LEN_MARKER:X},实际 0x{head:X}"
        ));
    }
    let nt: [u8; 16] = body[4..20].try_into().unwrap_or([0; 16]);
    // 明文在 LM 之后、校验和之前可能有零填充；校验和位置由 lm_len 决定，
    // 不能直接用 body.len()-16，否则会把填充算进 LM 区。
    let checksum_at = 20usize
        .checked_add(lm_len)
        .filter(|offset| offset + 16 <= body.len())
        .ok_or_else(|| {
            format!(
                "AAD 校验失败:LM 长度 {} 与明文长度 {} 不相容",
                lm_len,
                body.len()
            )
        })?;
    let lm = if lm_len == 0 {
        None
    } else if lm_len == 16 {
        Some(<[u8; 16]>::try_from(&body[20..checksum_at]).unwrap_or([0; 16]))
    } else {
        return Err(format!(
            "AAD 校验失败:LM 区长度 {lm_len} 既不是 0 也不是 16"
        ));
    };
    let expected: [u8; 16] = body[checksum_at..checksum_at + 16]
        .try_into()
        .unwrap_or([0; 16]);
    let mut hashed = Vec::with_capacity(32);
    hashed.extend_from_slice(&nt);
    if let Some(lm_bytes) = &lm {
        hashed.extend_from_slice(lm_bytes);
    }
    let actual = md4(&hashed);
    if actual != expected {
        return Err(format!(
            "AAD 校验失败:NT/LM 校验和不匹配(期望 {},实际 {})",
            hex_lower(&expected),
            hex_lower(&actual)
        ));
    }
    Ok((nt, lm))
}

/// 从 `Users\Names\<name>` 的默认值 0x34 处读取本地域 SID。
/// 只接受 S-1-5-21-a-b-c 形态；找不到/不唯一时返回 None，不猜。
pub fn domain_sid(hive: &Hive) -> Option<Sid> {
    let names = hive
        .open_key(&["SAM", "Domains", "Account", "Names"])
        .or_else(|_| hive.open_key(&["Domains", "Account", "Names"]))
        .ok()?;
    for child in hive.subkey_cells(names).ok()? {
        let values = hive.values(child).ok()?;
        let Some(default) = values.iter().find(|value| value.name.is_empty()) else {
            continue;
        };
        let data = hive.value_data(default).ok()?;
        let Some(sid) = data.get(0x34..).and_then(Sid::parse) else {
            continue;
        };
        if sid.revision == 1
            && sid.authority == 5
            && sid.sub_authorities.len() == crate::sid::DOMAIN_SUB_AUTHORITIES
        {
            return Some(sid);
        }
    }
    None
}

/// 遍历 `Users` 下所有 8 位十六进制子键并提取。
pub fn extract_accounts(hive: &Hive, keys: &HashKeys) -> RegfResult<Vec<AccountRecord>> {
    // 真实 SAM hive 常见 根 SAM -> 子 SAM -> Domains；部分合成/导出
    // hive 只有 根 SAM -> Domains。两种布局都接受。
    let users_cell = hive
        .open_key(&USERS_PATH)
        .or_else(|_| hive.open_key(&["Domains", "Account", "Users"]))?;
    let domain = domain_sid(hive);
    let mut records = Vec::new();
    for cell in hive.subkey_cells(users_cell)? {
        let name = hive.key_name_at(cell)?;
        if !is_rid_key(&name) {
            continue;
        }
        match extract_user(hive, cell, &name, keys) {
            Ok(mut record) => {
                record.account_sid = domain
                    .as_ref()
                    .and_then(|domain| compose_sid(domain, record.rid));
                records.push(record)
            }
            Err(reason) => crate::logger::warn(&format!("用户键 {name} 提取失败: {reason}")),
        }
    }
    records.sort_by_key(|record| record.rid);
    Ok(records)
}

/// 全流程结果
#[derive(Debug)]
pub struct Extraction {
    pub bootkey: BootKey,
    pub accounts: Vec<AccountRecord>,
    pub limitations: Vec<String>,
}

/// bootkey 派生 → FakeBootKey(可选)→ 账号与哈希提取
pub fn extract(system: &Hive, sam: &Hive) -> Result<Extraction, String> {
    let bootkey = crate::bootkey::derive_bootkey(system)
        .map_err(|error| format!("bootkey 派生失败({})", error.describe()))?;
    let (fake, mut limitations) = try_fake_boot_key(sam);
    let keys = hash_keys(&bootkey.key, fake);
    limitations.extend(keys.notes.clone());
    let accounts = extract_accounts(sam, &keys)
        .map_err(|error| format!("账号提取失败({})", error.describe()))?;
    Ok(Extraction {
        bootkey,
        accounts,
        limitations,
    })
}
