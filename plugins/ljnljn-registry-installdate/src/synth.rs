//! 合成 regf hive 构建器（单元测试与独立 fixture 生成工具共用）。
//!
//! 自底向上生成 base block、hbin 块与 cell 树：
//!   1. 先写所有 cell（nk / vk / 数据 / 子键列表 / 值列表 / 大值分段）；
//!   2. cell 偏移一律记录为「相对首个 hbin 起点（文件 0x1000）」的**带前缀 cell 头**偏移；
//!   3. 放不下就新开 4096 字节 hbin，块内剩余空间写成空闲 cell；
//!   4. 最后回填 base block 的根键偏移（= 根 nk 的**载荷**偏移，符合真实 hive 的写法）、
//!      hive bins 长度与校验和。
//!
//! 覆盖的写法差异（都是规范允许的）：
//! * 键名压缩（nk flags 0x20，ASCII 内联）与非压缩（UTF-16 放独立 cell）；
//! * 值名 UTF-16 与压缩 ASCII；
//! * 子键列表 `lf` / `lh` / `li` / `ri`；
//! * 值数据内联（≤ 4 字节）、普通数据 cell、`db` 大值分段。
//!
//! 这是一个**独立实现**（不复用解析器代码计算任何偏移），因此能被解析器当作
//! 外部样例使用；手工计算的对照时间写在 `tests.rs` / fixture 清单里。

use crate::regf::{compute_checksum, BASE_BLOCK_SIZE};

const BIN_SIZE: usize = 4096;
const BIN_HEADER: usize = 32;

/// 合成用的值类型号。
pub const REG_SZ: u32 = 1;
pub const REG_BINARY: u32 = 3;
pub const REG_DWORD: u32 = 4;
pub const REG_DWORD_BIG_ENDIAN: u32 = 5;
pub const REG_MULTI_SZ: u32 = 7;

/// 子键列表形态。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndexKind {
    Lf,
    Lh,
    Li,
    /// `ri` 包裹若干 `li`（覆盖多级索引）。
    Ri,
}

/// 名字编码。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameEncoding {
    /// nk/vk flags 的压缩位：ASCII 内联，非 ASCII 字节按 Latin-1 提升。
    Compressed,
    /// UTF-16LE（键名放独立 cell，值名附在 vk 尾部）。
    Utf16,
}

/// 要写入的一个值。
#[derive(Clone, Debug)]
pub struct ValueSpec {
    pub name: String,
    pub value_type: u32,
    pub data: Vec<u8>,
    pub name_encoding: NameEncoding,
    /// 强制写成 `db` 大值分段（即使数据很短）。
    pub force_big_data: bool,
    /// 覆盖 vk 的声明长度（模拟损坏：声明比实际大）。
    pub declared_len_override: Option<u32>,
}

impl ValueSpec {
    pub fn sz(name: &str, text: &str) -> Self {
        Self::raw(name, REG_SZ, utf16z(text))
    }

    pub fn dword(name: &str, value: u32) -> Self {
        Self::raw(name, REG_DWORD, value.to_le_bytes().to_vec())
    }

    pub fn binary(name: &str, bytes: &[u8]) -> Self {
        Self::raw(name, REG_BINARY, bytes.to_vec())
    }

    pub fn multi_sz(name: &str, parts: &[&str]) -> Self {
        let mut data = Vec::new();
        for part in parts {
            data.extend(utf16z(part));
        }
        data.extend([0_u8, 0]);
        Self::raw(name, REG_MULTI_SZ, data)
    }

    pub fn raw(name: &str, value_type: u32, data: Vec<u8>) -> Self {
        Self {
            name: name.to_owned(),
            value_type,
            data,
            name_encoding: NameEncoding::Utf16,
            force_big_data: false,
            declared_len_override: None,
        }
    }

    pub fn with_name_encoding(mut self, encoding: NameEncoding) -> Self {
        self.name_encoding = encoding;
        self
    }

    pub fn with_big_data(mut self) -> Self {
        self.force_big_data = true;
        self
    }

    pub fn with_declared_len(mut self, declared: u32) -> Self {
        self.declared_len_override = Some(declared);
        self
    }
}

/// 要写入的一个键。
#[derive(Clone, Debug)]
pub struct KeySpec {
    pub name: String,
    pub encoding: NameEncoding,
    pub values: Vec<ValueSpec>,
    pub children: Vec<KeySpec>,
    pub index: IndexKind,
    /// last write（FILETIME；0 = 未设置）。
    pub last_write: u64,
}

impl KeySpec {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_owned(),
            encoding: NameEncoding::Compressed,
            values: Vec::new(),
            children: Vec::new(),
            index: IndexKind::Lh,
            last_write: 0,
        }
    }

    pub fn with_values(name: &str, values: Vec<ValueSpec>) -> Self {
        let mut key = Self::new(name);
        key.values = values;
        key
    }

    pub fn child(mut self, child: KeySpec) -> Self {
        self.children.push(child);
        self
    }

    pub fn with_encoding(mut self, encoding: NameEncoding) -> Self {
        self.encoding = encoding;
        self
    }

    pub fn with_index(mut self, index: IndexKind) -> Self {
        self.index = index;
        self
    }

    pub fn with_last_write(mut self, filetime: u64) -> Self {
        self.last_write = filetime;
        self
    }
}

/// hive 头部覆盖项（用于构造损坏样例）。
#[derive(Clone, Debug, Default)]
pub struct HeaderPatch {
    /// 覆盖魔数（默认 `regf`）。
    pub magic: Option<[u8; 4]>,
    /// 覆盖 0x14/0x18 主/次版本。
    pub version: Option<(u32, u32)>,
    /// 覆盖 0x1c 文件类型。
    pub file_type: Option<u32>,
    /// 覆盖 0x28 hive bins 数据长度。
    pub hbins_size: Option<u32>,
    /// 覆盖 0x24 根键偏移。
    pub root_cell: Option<u32>,
    /// 覆盖 0x1fc 校验和（`Some(0)` = 占位）。
    pub checksum: Option<u32>,
    /// 序列号（默认 7/7）。
    pub sequences: Option<(u32, u32)>,
    /// 头部 last write（默认 2024-01-01T00:00:00Z）。
    pub last_write: Option<u64>,
    /// 文件名（默认 `SOFTWARE`）。
    pub file_name: Option<String>,
    /// 生成后截断到该字节数（模拟截断的 hive）。
    pub truncate_to: Option<usize>,
}

struct Cell {
    /// 长度前缀绝对值（8 字节对齐后的含前缀总长）。
    total: usize,
    payload: Vec<u8>,
    /// 写入内容后把 payload 覆盖成另一种字节（模拟损坏）。
    overwrite: Option<Vec<u8>>,
}

/// 自底向上构建 hive。
pub struct HiveBuilder {
    bins: Vec<Vec<Cell>>,
}

impl Default for HiveBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn align8(value: usize) -> usize {
    value + (8 - value % 8) % 8
}

pub fn utf16_le_bytes(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(|unit| unit.to_le_bytes()).collect()
}

fn utf16z(text: &str) -> Vec<u8> {
    let mut bytes = utf16_le_bytes(text);
    bytes.extend([0_u8, 0]);
    bytes
}

impl HiveBuilder {
    pub fn new() -> Self {
        Self {
            bins: vec![Vec::new()],
        }
    }

    fn used(bin: &[Cell]) -> usize {
        bin.iter().map(|cell| cell.total).sum()
    }

    fn alloc(&mut self, payload: Vec<u8>) -> u32 {
        self.alloc_with(payload, None)
    }

    fn alloc_with(&mut self, payload: Vec<u8>, overwrite: Option<Vec<u8>>) -> u32 {
        let total = align8(payload.len() + 4);
        let mut payload = payload;
        payload.resize(total - 4, 0);
        let last = self.bins.len() - 1;
        // hbin 内可用于 cell 的空间是 BIN_SIZE - BIN_HEADER。
        // 单个 cell 可能超过这个空间（大值分段最大 16344 字节），这时它会独占一个 hbin
        // 并越过块尾；因此这里只要求“已经装了东西的 hbin 不再追加装不下的 cell”。
        let room = BIN_SIZE - BIN_HEADER;
        let already_used = Self::used(&self.bins[last]);
        let oversized = total > room;
        if !self.bins[last].is_empty() && (already_used + total > room) {
            self.bins.push(Vec::new());
        }
        // 放得下的正常 cell 结束后若剩余空间不足，后续 cell 会再开新 hbin。
        let _ = oversized;
        let bin_index = self.bins.len() - 1;
        let used = Self::used(&self.bins[bin_index]);
        let file_offset = BASE_BLOCK_SIZE as usize + bin_index * BIN_SIZE + BIN_HEADER + used;
        self.bins[bin_index].push(Cell {
            total,
            payload,
            overwrite,
        });
        (file_offset - BASE_BLOCK_SIZE as usize) as u32
    }

    fn index(&mut self, kind: IndexKind, entries: &[(String, u32)]) -> u32 {
        match kind {
            IndexKind::Ri => {
                let mut parts = Vec::new();
                for chunk in entries.chunks(2).filter(|chunk| !chunk.is_empty()) {
                    parts.push(self.index(IndexKind::Li, chunk));
                }
                let mut payload = Vec::new();
                payload.extend_from_slice(b"ri");
                payload.extend_from_slice(&(parts.len() as u16).to_le_bytes());
                for part in parts {
                    payload.extend_from_slice(&part.to_le_bytes());
                }
                self.alloc(payload)
            }
            IndexKind::Li => {
                let mut payload = Vec::new();
                payload.extend_from_slice(b"li");
                payload.extend_from_slice(&(entries.len() as u16).to_le_bytes());
                for (_, offset) in entries {
                    payload.extend_from_slice(&offset.to_le_bytes());
                }
                self.alloc(payload)
            }
            IndexKind::Lf | IndexKind::Lh => {
                let signature: &[u8; 2] = if kind == IndexKind::Lf { b"lf" } else { b"lh" };
                let mut payload = Vec::new();
                payload.extend_from_slice(signature);
                payload.extend_from_slice(&(entries.len() as u16).to_le_bytes());
                for (name, offset) in entries {
                    payload.extend_from_slice(&offset.to_le_bytes());
                    payload.extend_from_slice(&index_hash(name).to_le_bytes());
                }
                self.alloc(payload)
            }
        }
    }

    fn value_list(&mut self, offsets: &[u32]) -> u32 {
        let mut payload = Vec::new();
        for offset in offsets {
            payload.extend_from_slice(&offset.to_le_bytes());
        }
        self.alloc(payload)
    }

    fn vk(&mut self, spec: &ValueSpec) -> u32 {
        // 
        // `vk` 的 `name_len` 是名称占用的字节数（含结尾 NUL 字符）。
        let (name_bytes, name_flag) = match spec.name_encoding {
            NameEncoding::Utf16 => (utf16z(&spec.name), 0_u16),
            NameEncoding::Compressed => {
                let mut bytes: Vec<u8> = spec.name.chars().map(|c| c as u32 as u8).collect();
                bytes.push(0);
                (bytes, 1_u16)
            }
        };
        let declared = u32::try_from(spec.data.len()).unwrap_or(u32::MAX);
        let (len_field, offset_field, overwrite) = if spec.force_big_data {
            let data_cell = self.big_data_cell(&spec.data);
            (declared, data_cell, None)
        } else if spec.data.len() <= 4 {
            let mut inline = [0_u8; 4];
            inline[..spec.data.len()].copy_from_slice(&spec.data);
            (declared | 0x8000_0000, u32::from_le_bytes(inline), None)
        } else {
            let data_cell = self.alloc(spec.data.clone());
            (declared, data_cell, None)
        };
        // 覆盖声明长度时保留内联标志位（0x8000_0000），否则内联值会被当成数据单元偏移读。
        let len_field = match spec.declared_len_override {
            Some(custom) => (custom & !0x8000_0000) | (len_field & 0x8000_0000),
            None => len_field,
        };
        let mut payload = vec![0_u8; 0x14];
        payload[0..2].copy_from_slice(b"vk");
        payload[2..4].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        payload[4..8].copy_from_slice(&len_field.to_le_bytes());
        payload[8..12].copy_from_slice(&offset_field.to_le_bytes());
        payload[0x0c..0x10].copy_from_slice(&spec.value_type.to_le_bytes());
        payload[0x10..0x12].copy_from_slice(&name_flag.to_le_bytes());
        payload.extend_from_slice(&name_bytes);
        self.alloc_with(payload, overwrite)
    }

    /// `db` 大值单元：0x00 "db" 0x02 段数 0x04 段列表偏移；段列表里是各分段 cell 偏移。
    fn big_data_cell(&mut self, data: &[u8]) -> u32 {
        let chunk_size = 16344;
        let mut segment_offsets = Vec::new();
        for chunk in data.chunks(chunk_size) {
            segment_offsets.push(self.alloc(chunk.to_vec()));
        }
        let mut list = Vec::new();
        for offset in &segment_offsets {
            list.extend_from_slice(&offset.to_le_bytes());
        }
        let list_cell = self.alloc(list);
        let mut payload = Vec::new();
        payload.extend_from_slice(b"db");
        payload.extend_from_slice(&(segment_offsets.len() as u16).to_le_bytes());
        payload.extend_from_slice(&list_cell.to_le_bytes());
        self.alloc(payload)
    }

    fn nk(&mut self, spec: &KeySpec, subkeys: &[(String, u32)], values: &[u32]) -> u32 {
        // 两种编码都把名称存放在独立的名称单元里，nk 的 0x4c 字段只放单元偏移
        // （真实 hive 的写法；0x20 标志位表示名称可压缩为单字节，解析器据此解码）。
        let name_bytes = match spec.encoding {
            NameEncoding::Compressed => {
                let mut bytes = spec.name.as_bytes().to_vec();
                bytes.push(0);
                bytes
            }
            NameEncoding::Utf16 => utf16z(&spec.name),
        };
        let name_area = self.alloc(name_bytes.clone());
        let (sub_count, sub_list) = if subkeys.is_empty() {
            (0, crate::regf::NO_CELL)
        } else {
            let list = self.index(spec.index, subkeys);
            (u32::try_from(subkeys.len()).unwrap_or(0), list)
        };
        let (val_count, val_list) = if values.is_empty() {
            (0, crate::regf::NO_CELL)
        } else {
            (u32::try_from(values.len()).unwrap_or(0), self.value_list(values))
        };
        let mut payload = vec![0_u8; 0x4c];
        payload[0..2].copy_from_slice(b"nk");
        let flags = if spec.encoding == NameEncoding::Compressed {
            0x20_u16
        } else {
            0x00_u16
        };
        payload[2..4].copy_from_slice(&flags.to_le_bytes());
        payload[0x04..0x0c].copy_from_slice(&spec.last_write.to_le_bytes());
        payload[0x14..0x18].copy_from_slice(&sub_count.to_le_bytes());
        payload[0x1c..0x20].copy_from_slice(&sub_list.to_le_bytes());
        payload[0x20..0x24].copy_from_slice(&crate::regf::NO_CELL.to_le_bytes());
        payload[0x24..0x28].copy_from_slice(&val_count.to_le_bytes());
        payload[0x28..0x2c].copy_from_slice(&val_list.to_le_bytes());
        // 0x48 = 名称字符数（含结尾 NUL 字符）；压缩名 1 字节/字符，UTF-16 2 字节/字符。
        let name_units = match spec.encoding {
            NameEncoding::Compressed => name_bytes.len(),
            NameEncoding::Utf16 => name_bytes.len() / 2,
        };
        payload[0x48..0x4a].copy_from_slice(&(name_units as u16).to_le_bytes());
        payload[0x4a..0x4c].copy_from_slice(&0_u16.to_le_bytes());
        payload.extend_from_slice(&name_area.to_le_bytes());
        self.alloc(payload)
    }

    fn write_tree(&mut self, spec: &KeySpec) -> u32 {
        let mut value_offsets = Vec::new();
        for value in &spec.values {
            value_offsets.push(self.vk(value));
        }
        let mut children = Vec::new();
        for child in &spec.children {
            let offset = self.write_tree(child);
            children.push((child.name.clone(), offset));
        }
        children.sort_by(|left, right| upper(&left.0).cmp(&upper(&right.0)));
        self.nk(spec, &children, &value_offsets)
    }

    /// 生成完整 hive 字节；返回字节与根键 nk 的 cell 头偏移（相对首个 hbin）。
    pub fn build(&mut self, root: &KeySpec, patch: &HeaderPatch) -> (Vec<u8>, u32) {
        let root_cell = self.write_tree(root);
        let bin_count = self.bins.len();
        let hbins_size = (bin_count * BIN_SIZE) as u32;
        let mut out = vec![0_u8; BASE_BLOCK_SIZE as usize + bin_count * BIN_SIZE];
        out[0..4].copy_from_slice(&patch.magic.unwrap_or(*b"regf"));
        let (sequence1, sequence2) = patch.sequences.unwrap_or((7, 7));
        out[0x04..0x08].copy_from_slice(&sequence1.to_le_bytes());
        out[0x08..0x0c].copy_from_slice(&sequence2.to_le_bytes());
        let last_write = patch.last_write.unwrap_or(133_479_208_800_000_000); // 2024-01-01Z
        out[0x0c..0x14].copy_from_slice(&last_write.to_le_bytes());
        let (major, minor) = patch.version.unwrap_or((1, 5));
        out[0x14..0x18].copy_from_slice(&major.to_le_bytes());
        out[0x18..0x1c].copy_from_slice(&minor.to_le_bytes());
        out[0x1c..0x20].copy_from_slice(&patch.file_type.unwrap_or(0).to_le_bytes());
        out[0x20..0x24].copy_from_slice(&1_u32.to_le_bytes()); // 直接内存载入
        // 根键偏移 = nk 载荷位置（真实 hive 的写法），即 cell 头 + 4。
        let root_payload = root_cell + 4;
        out[0x24..0x28].copy_from_slice(&patch.root_cell.unwrap_or(root_payload).to_le_bytes());
        out[0x28..0x2c].copy_from_slice(&patch.hbins_size.unwrap_or(hbins_size).to_le_bytes());
        out[0x2c..0x30].copy_from_slice(&1_u32.to_le_bytes()); // clustering factor
        let file_name = patch.file_name.clone().unwrap_or_else(|| "SOFTWARE".to_owned());
        let mut name_bytes = utf16_le_bytes(&file_name);
        name_bytes.truncate(64);
        out[0x30..0x30 + name_bytes.len()].copy_from_slice(&name_bytes);
        // 校验和字段不在异或范围内：默认写入计算值。
        let checksum = patch
            .checksum
            .unwrap_or_else(|| compute_checksum(&out[..BASE_BLOCK_SIZE as usize]));
        out[0x1fc..0x200].copy_from_slice(&checksum.to_le_bytes());
        for (index, bin) in self.bins.iter().enumerate() {
            let bin_start = BASE_BLOCK_SIZE as usize + index * BIN_SIZE;
            let bin_end = bin_start + BIN_SIZE;
            let mut cursor = bin_start + BIN_HEADER;
            // hbin 内的可用空间只到 bin_end；单个 cell 超过这个空间时（例如大值分段
            // 最大 16344 字节，而 hbin 只有 0x1000）它独占本块，写入长度以块尾为界。
            for cell in bin {
                if cursor >= bin_end {
                    break;
                }
                let room = bin_end - cursor;
                let take = cell.payload.len().min(room.saturating_sub(4));
                let declared = if room >= cell.total { cell.total } else { room };
                out[cursor..cursor + 4].copy_from_slice(&(-(declared as i32)).to_le_bytes());
                match &cell.overwrite {
                    Some(bytes) => {
                        let take = take.min(bytes.len());
                        out[cursor + 4..cursor + 4 + take].copy_from_slice(&bytes[..take]);
                    }
                    None => {
                        out[cursor + 4..cursor + 4 + take].copy_from_slice(&cell.payload[..take])
                    }
                }
                cursor += declared;
            }
            let remaining = bin_end.saturating_sub(cursor);
            if remaining >= 4 {
                out[cursor..cursor + 4].copy_from_slice(&(remaining as i32).to_le_bytes());
            }
            out[bin_start..bin_start + 4].copy_from_slice(b"hbin");
            out[bin_start + 4..bin_start + 8]
                .copy_from_slice(&((bin_start - BASE_BLOCK_SIZE as usize) as u32).to_le_bytes());
            out[bin_start + 8..bin_start + 12].copy_from_slice(&(BIN_SIZE as u32).to_le_bytes());
        }
        if let Some(limit) = patch.truncate_to {
            out.truncate(limit.min(out.len()));
        }
        (out, root_cell)
    }
}

fn upper(name: &str) -> String {
    name.to_ascii_uppercase()
}

/// `lf`/`lh` 条目的 4 字节名字 hash（大写后按 UTF-16 码元 ×37 累加，取低 31 位）。
fn index_hash(name: &str) -> u32 {
    let mut hash: u32 = 0;
    for unit in upper(name).encode_utf16() {
        hash = hash.wrapping_mul(37).wrapping_add(u32::from(unit));
    }
    hash & 0x7fff_ffff
}

// ---------------------------------------------------------------------------
// 样例树
// ---------------------------------------------------------------------------

/// 目标键下的“正常”属性集（不含 InstallDate）。
pub fn current_version_values() -> Vec<ValueSpec> {
    vec![
        ValueSpec::sz("ProductName", "Windows 10 Pro"),
        ValueSpec::sz("CurrentBuild", "19041"),
        ValueSpec::sz("CurrentBuildNumber", "19041"),
        ValueSpec::sz("CurrentVersion", "10.0"),
        ValueSpec::dword("CurrentMajorVersionNumber", 10),
        ValueSpec::dword("CurrentMinorVersionNumber", 0),
        ValueSpec::sz("DisplayVersion", "2004"),
        ValueSpec::sz("EditionID", "Professional"),
        ValueSpec::sz("ProductId", "00330-80000-00000-AA000"),
        ValueSpec::dword("UBR", 1234),
    ]
}

/// 在标准属性集后追加一个 `InstallDate` 值。
pub fn current_version_with(install_date: Option<ValueSpec>) -> Vec<ValueSpec> {
    let mut values = current_version_values();
    if let Some(value) = install_date {
        values.push(value);
    }
    values
}

/// 标准 SOFTWARE 树：`Microsoft\Windows NT\CurrentVersion` + 干扰键。
///
/// 干扰项：`Microsoft\Windows NT\Run`（含同名 `InstallDate` 的诱饵值）、
/// `Classes`、`Microsoft\Windows\CurrentVersion`（缺失一层 `Windows NT`）。
pub fn software_tree(current_version: KeySpec) -> KeySpec {
    let run = KeySpec::with_values(
        "Run",
        vec![
            ValueSpec::sz("NotUsed", "C:\\Windows\\not-used.exe"),
            ValueSpec::dword("InstallDate", 1_000_000_000),
        ],
    );
    let windows_nt = KeySpec::new("Windows NT")
        .with_index(IndexKind::Lh)
        .child(current_version)
        .child(run);
    let microsoft = KeySpec::new("Microsoft")
        .with_index(IndexKind::Ri)
        .child(windows_nt);
    let classes = KeySpec::with_values("Classes", vec![ValueSpec::sz("Ignore", "x")]);
    KeySpec::new("SOFTWARE")
        .with_index(IndexKind::Lf)
        .child(microsoft)
        .child(classes)
}

/// 生成一个正常 SOFTWARE 样例（InstallDate 为 REG_DWORD）。
pub fn build_dword_hive(install_date: u32) -> Vec<u8> {
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::dword("InstallDate", install_date))),
    )
    .with_last_write(133_479_208_800_000_000);
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::regf::{Hive, SliceReader};

    #[test]
    fn synthetic_hive_has_valid_header_and_root() {
        let bytes = build_dword_hive(1_620_038_668);
        assert_eq!(&bytes[0..4], b"regf");
        assert_eq!(&bytes[0x1000..0x1004], b"hbin");
        let hive = Hive::open(SliceReader::new(&bytes)).expect("open");
        assert!(hive.header().checksum_ok());
        assert_eq!(hive.header().file_name, "SOFTWARE");
        assert_eq!(hive.header().version(), "1.5");
        let root = hive.root_key().expect("root");
        assert_eq!(root.name, "SOFTWARE");
        assert!(root.subkey_count >= 2);
    }

    #[test]
    fn every_index_kind_is_parseable() {
        for kind in [IndexKind::Lf, IndexKind::Lh, IndexKind::Li, IndexKind::Ri] {
            let key = KeySpec::with_values(
                "CurrentVersion",
                current_version_with(Some(ValueSpec::dword("InstallDate", 1_620_038_668))),
            );
            let mut tree = software_tree(key);
            tree.index = kind;
            if let Some(microsoft) = tree.children.iter_mut().find(|child| child.name == "Microsoft")
            {
                microsoft.index = kind;
            }
            let (bytes, _) = HiveBuilder::new().build(&tree, &HeaderPatch::default());
            let hive = Hive::open(SliceReader::new(&bytes)).expect("open");
            let found = hive
                .lookup_path_verbose(&["Microsoft", "Windows NT", "CurrentVersion"])
                .expect("lookup");
            assert!(found.key.is_some(), "索引 {kind:?} 下目标键应存在");
        }
    }
}
