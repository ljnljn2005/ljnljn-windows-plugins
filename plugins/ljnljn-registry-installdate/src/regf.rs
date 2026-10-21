//! Windows Registry hive（regf / ntreg 格式）只读解析器。
//!
//! 输入是一个 [`ReadAt`] 句柄（SDK 单文件句柄、检材卷内路径，或单元测试里的内存
//! 切片）。解析只做定长偏移读取，从不把整个 hive 读进内存，也不写入任何数据；
//! 所有长度与偏移都先校验再索引，绝不 panic。
//!
//! 已核对的磁盘结构（偏移相对 base block 或 cell 起点）：
//!
//! ```text
//! regf base block（0x1000 字节）
//!   0x00 "regf"                  0x04 / 0x08 primary / secondary sequence
//!   0x14 major    0x18 minor     0x1c 文件类型（0 = 主文件，1 = 事务日志）
//!   0x20 文件格式  0x24 根单元格偏移（相对首个 hbin）  0x28 hive bins 数据长度
//!   0x2c clustering 0x30 文件名（UTF-16LE，64 字节）
//!   0x1fc 校验和（0x00..0x1fb 共 127 个 u32 异或；0 表示 Windows 未写入）
//! hbin 块（文件 0x1000 起，长度 0x1000 的整数倍）
//!   0x00 "hbin"  0x04 相对首个 hbin 的偏移  0x08 本块长度
//! cell（块内 8 字节对齐）
//!   前缀 i32 size：负 = 已分配，正 = 空闲；载荷紧随 4 字节之后
//! nk（键节点载荷）
//!   0x00 "nk"  0x02 flags(0x20 = ASCII/压缩键名)  0x04 last write(FILETIME)
//!   0x14 子键数  0x1c 子键列表偏移  0x20 volatile 子键数
//!   0x24 值数    0x28 值列表偏移
//!   0x48 键名长度 0x4a 类名长度 0x4c 键名（压缩时内联）或名字单元偏移
//! vk（值节点载荷）
//!   0x00 "vk"  0x02 值名长度（含结尾 NUL 的字节数）  0x04 数据长度（最高位 = 内联）
//!   0x08 数据偏移（内联时为数据本体）  0x0c 类型  0x10 flags(0x0001 = ASCII 值名)
//!   0x14 值名
//! 子键列表：lf / lh（4B 偏移 + 4B hash）、li（4B 偏移）、ri（4B 子列表偏移）
//! 值列表：连续的 u32 vk 单元偏移，数量取自 nk 的 0x24
//! 大值（数据单元载荷首 2 字节为 "db"）：0x00 "db" 0x02 段数 0x04 段列表偏移
//! ```
//!
//! **偏移语义**：base block 0x24 的根键偏移是「相对首个 hbin 起点」的值（该位置
//! 只有 cell 载荷、没有 4 字节长度前缀）；而 nk / vk / 列表里的所有偏移都指向
//! 「带长度前缀的 cell 头」。解析时先按带前缀的 cell 定位，若签名不匹配再按
//! 「相对 hbin 的载荷位置」解释，两种写法都能读，且只有签名吻合时才接受。

/// hive 文件头长度（base block）。
pub const BASE_BLOCK_SIZE: u64 = 0x1000;
/// hbin 块头长度（hbin / 偏移 / 长度 / 时间戳 / 保留）。
pub const MIN_HBIN_HEADER: u64 = 0x20;
/// 一个 hbin 的最小长度。
pub const MIN_HBIN_SIZE: u32 = 0x1000;
/// 单个 hbin 长度上限（1 GiB），防止畸形头导致整块读入内存。
#[allow(dead_code)]
pub const MAX_HBIN_SIZE: u32 = 0x4000_0000;
/// 单个 cell 载荷上限（256 MiB）。
pub const MAX_CELL_SIZE: u32 = 0x1000_0000;
/// 单个值原始数据上限。
pub const MAX_VALUE_BYTES: u32 = 0x800_0000;
/// 单个大值分段载荷上限（Windows 写 16344 字节，留余量）。
pub const MAX_BIG_SEGMENT: u32 = 0x1_0000;
/// 列表条目上限。
pub const MAX_LIST_ENTRIES: usize = 1 << 20;
/// `ri` 索引嵌套深度上限。
pub const MAX_RI_DEPTH: usize = 8;
/// 键路径段数上限。
pub const MAX_PATH_DEPTH: usize = 32;

const KEY_COMP_NAME: u16 = 0x0020;
const VALUE_INLINE_DATA: u32 = 0x8000_0000;
const VALUE_COMP_NAME: u16 = 0x0001;

// ---------------------------------------------------------------------------
// 数据类型
// ---------------------------------------------------------------------------

/// 注册表值类型（只区分本插件需要的几种；其它保留原始类型号）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValueType {
    /// REG_NONE
    None,
    /// REG_SZ
    Sz,
    /// REG_EXPAND_SZ
    ExpandSz,
    /// REG_BINARY
    Binary,
    /// REG_DWORD
    Dword,
    /// REG_DWORD_BIG_ENDIAN
    DwordBigEndian,
    /// REG_LINK
    Link,
    /// REG_MULTI_SZ
    MultiSz,
    /// REG_QWORD
    Qword,
    /// 其它（保留原始类型号）
    Other(u32),
}

impl ValueType {
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::None,
            1 => Self::Sz,
            2 => Self::ExpandSz,
            3 => Self::Binary,
            4 => Self::Dword,
            5 => Self::DwordBigEndian,
            6 => Self::Link,
            7 => Self::MultiSz,
            11 => Self::Qword,
            other => Self::Other(other),
        }
    }

    /// regedit 使用的类型名（REG_*），未知类型带原始类型号。
    pub fn name(self) -> String {
        match self {
            Self::None => "REG_NONE".to_owned(),
            Self::Sz => "REG_SZ".to_owned(),
            Self::ExpandSz => "REG_EXPAND_SZ".to_owned(),
            Self::Binary => "REG_BINARY".to_owned(),
            Self::Dword => "REG_DWORD".to_owned(),
            Self::DwordBigEndian => "REG_DWORD_BIG_ENDIAN".to_owned(),
            Self::Link => "REG_LINK".to_owned(),
            Self::MultiSz => "REG_MULTI_SZ".to_owned(),
            Self::Qword => "REG_QWORD".to_owned(),
            Self::Other(raw) => format!("REG_UNKNOWN(0x{raw:x})"),
        }
    }
}

/// 解码后的值内容。
#[derive(Clone, Debug, PartialEq)]
pub enum ValueData {
    /// 字符串值（REG_SZ / REG_EXPAND_SZ / REG_LINK / REG_MULTI_SZ）。
    Text(String),
    /// 32 位整数（REG_DWORD / REG_DWORD_BIG_ENDIAN）。
    Dword(u32),
    /// 64 位整数（REG_QWORD）。
    Qword(u64),
    /// 其它原始字节。
    Bytes(Vec<u8>),
}

impl ValueData {
    /// 表格里展示的文本：字符串原样、整数十进制、字节十六进制。
    pub fn display(&self) -> String {
        match self {
            Self::Text(text) => text.clone(),
            Self::Dword(value) => format!("{value}"),
            Self::Qword(value) => format!("{value}"),
            Self::Bytes(bytes) => hex_bytes(bytes),
        }
    }
}

/// “无单元”哨兵值（regf 用 0xFFFFFFFF 表示空列表/无数据）。
pub const NO_CELL: u32 = 0xFFFF_FFFF;

/// `vk` 解析结果。
#[derive(Clone, Debug, PartialEq)]
pub struct HiveValue {
    /// 值名（空字符串表示默认值 `(Default)`）。
    pub name: String,
    pub value_type: ValueType,
    /// `vk + 0x0c` 的原始类型号。
    pub raw_type: u32,
    /// `vk + 0x10` 的 flags 原值。
    pub flags: u16,
    /// 声明的原始数据长度（不含内联位）。
    pub declared_len: u32,
    /// 原始数据是否内联在 `vk` 中。
    pub inline: bool,
    /// 数据是否存放在 `db` 大值分段里。
    pub big_data: bool,
    /// 数据所在 cell 偏移（内联或空值时 `NO_CELL`）。
    pub data_cell: u32,
    /// `vk` cell 偏移（定位线索）。
    pub vk_cell: u32,
    /// 原始数据前 64 字节的十六进制。
    pub raw_hex: String,
    /// 解码后的数据。
    pub data: ValueData,
    /// 实际读到的原始字节数。
    pub raw_len: usize,
    /// 声明长度与实际读到长度不一致等非致命问题。
    pub truncated: bool,
}

impl HiveValue {
    pub fn text(&self) -> Option<&str> {
        match &self.data {
            ValueData::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn dword(&self) -> Option<u32> {
        match self.data {
            ValueData::Dword(value) => Some(value),
            _ => None,
        }
    }

    pub fn qword(&self) -> Option<u64> {
        match self.data {
            ValueData::Qword(value) => Some(value),
            _ => None,
        }
    }

    /// 原始数据字节（从 `raw_hex` 还原，不受类型解释影响）。
    pub fn raw_bytes(&self) -> Vec<u8> {
        if self.raw_hex.is_empty() || self.raw_hex == "(空)" {
            return Vec::new();
        }
        self.raw_hex
            .split_whitespace()
            .filter_map(|token| u8::from_str_radix(token, 16).ok())
            .collect()
    }

    pub fn bytes(&self) -> Option<&[u8]> {
        match &self.data {
            ValueData::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// 错误
// ---------------------------------------------------------------------------

/// 解析错误的分类（同时作为报告里的错误码）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// 读取失败（宿主句柄错误、短读）。
    Read,
    /// 不是 regf 文件（魔数 / bins 头 / 长度不符）。
    BadSignature,
    /// 结构性不一致（序列号、事务日志标志、非法长度）。
    Corrupt,
    /// 越界偏移、非法长度、非法签名。
    OutOfBounds,
    /// 超出资源上限（深度、体积）。
    ResourceLimit,
    /// 事务日志头（file type = 1），不是主 hive。
    LogHeader,
}

impl ErrorKind {
    pub fn code(self) -> &'static str {
        match self {
            Self::Read => "HIVE_READ_FAILED",
            Self::BadSignature => "HIVE_BAD_SIGNATURE",
            Self::Corrupt => "HIVE_CORRUPT",
            Self::OutOfBounds => "HIVE_OUT_OF_BOUNDS",
            Self::ResourceLimit => "HIVE_RESOURCE_LIMIT",
            Self::LogHeader => "HIVE_LOG_HEADER",
        }
    }
}

/// 带文件偏移的结构化解析错误。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HiveError {
    pub kind: ErrorKind,
    /// 出错位置（文件绝对偏移；未知时为 0）。
    pub file_offset: u64,
    pub detail: String,
}

impl HiveError {
    pub fn new(kind: ErrorKind, file_offset: u64, detail: impl Into<String>) -> Self {
        Self {
            kind,
            file_offset,
            detail: detail.into(),
        }
    }

    pub fn read(detail: impl Into<String>) -> Self {
        Self::new(ErrorKind::Read, 0, detail)
    }
}

impl std::fmt::Display for HiveError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{} @0x{:x}: {}",
            self.kind.code(),
            self.file_offset,
            self.detail
        )
    }
}

impl std::error::Error for HiveError {}

type Res<T> = std::result::Result<T, HiveError>;

// ---------------------------------------------------------------------------
// 只读来源
// ---------------------------------------------------------------------------

/// hive 字节来源。`offset` 是文件内绝对偏移；实现必须返回**恰好**请求的字节数
/// 或报错（不做零填充），解析器据此区分“越界”与“全零”。
pub trait ReadAt {
    fn size(&self) -> u64;
    fn read_at(&self, offset: u64, length: usize) -> std::result::Result<Vec<u8>, String>;
}

/// 在内存字节上实现 `ReadAt`（单元测试与协议验证工具使用）。
pub struct SliceReader<'a> {
    bytes: &'a [u8],
}

impl<'a> SliceReader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self { bytes }
    }
}

impl ReadAt for SliceReader<'_> {
    fn size(&self) -> u64 {
        self.bytes.len() as u64
    }

    fn read_at(&self, offset: u64, length: usize) -> std::result::Result<Vec<u8>, String> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let start = usize::try_from(offset).map_err(|_| format!("偏移 {offset} 超出地址空间"))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| format!("读取范围溢出: {start}+{length}"))?;
        if end > self.bytes.len() {
            return Err(format!(
                "短读: 需要 [0x{start:x},0x{end:x})，数据只有 0x{:x} 字节",
                self.bytes.len()
            ));
        }
        Ok(self.bytes[start..end].to_vec())
    }
}

/// 截断读取包装（验证“hive 文件被截断”分支时使用）。
#[allow(dead_code)]
pub struct Truncated<'a, S> {
    inner: S,
    limit: u64,
    _marker: std::marker::PhantomData<&'a ()>,
}

impl<'a, S: ReadAt> Truncated<'a, S> {
    #[allow(dead_code)]
    pub fn new(inner: S, limit: u64) -> Self {
        Self {
            inner,
            limit,
            _marker: std::marker::PhantomData,
        }
    }
}

impl<S: ReadAt> ReadAt for Truncated<'_, S> {
    fn size(&self) -> u64 {
        self.inner.size().min(self.limit)
    }

    fn read_at(&self, offset: u64, length: usize) -> std::result::Result<Vec<u8>, String> {
        if offset >= self.limit {
            return Err(format!("短读: 偏移 0x{offset:x} 已超出截断长度 0x{:x}", self.limit));
        }
        let available = (self.limit - offset).min(length as u64) as usize;
        let bytes = self.inner.read_at(offset, available)?;
        if bytes.len() != length {
            return Err(format!(
                "短读: 0x{offset:x} 处需要 {length} 字节，实际 {} 字节（文件截断）",
                bytes.len()
            ));
        }
        Ok(bytes)
    }
}

fn rd_u16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at.checked_add(2)?)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
}

fn rd_u32(bytes: &[u8], at: usize) -> Option<u32> {
    let slice = bytes.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

fn rd_i32(bytes: &[u8], at: usize) -> Option<i32> {
    rd_u32(bytes, at).map(|raw| raw as i32)
}

fn rd_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let slice = bytes.get(at..at.checked_add(8)?)?;
    let mut raw = [0_u8; 8];
    raw.copy_from_slice(slice);
    Some(u64::from_le_bytes(raw))
}

// ---------------------------------------------------------------------------
// base block
// ---------------------------------------------------------------------------

/// regf 文件头（base block）的字段与校验结论。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BaseBlock {
    pub sequence1: u32,
    pub sequence2: u32,
    /// 头部 last write（FILETIME 原值；0 表示 Windows 未写入）。
    pub last_write_raw: u64,
    pub major: u32,
    pub minor: u32,
    /// 0x1c 文件类型：0 = 主 hive，1 = 事务日志。
    pub file_type: u32,
    /// 0x20 文件格式：1 = 直接内存载入，2 = 分块（XP 及以后）。
    pub file_format: u32,
    /// 0x24 根键偏移（相对首个 hbin）。
    pub root_cell_offset: u32,
    /// 0x28 hive bins 数据长度。
    pub hbins_size: u32,
    /// 0x2c clustering factor。
    pub clustering: u32,
    /// 0x30 文件名（UTF-16LE）。
    pub file_name: String,
    /// 0x1fc 存储的校验和。
    pub checksum: u32,
    /// 按 0x00..0x1fb 的 u32 异或计算出的校验和。
    pub computed_checksum: u32,
}

impl BaseBlock {
    /// 存储校验和为 0（Windows 用 0 表示“未写入”，此时不做比对）。
    pub fn checksum_is_placeholder(&self) -> bool {
        self.checksum == 0
    }

    /// 校验和一致（或存储值为占位 0）。
    pub fn checksum_ok(&self) -> bool {
        self.checksum_is_placeholder() || self.checksum == self.computed_checksum
    }

    /// 两个序列号一致且非 0（未处于部分写状态）。
    pub fn sequences_consistent(&self) -> bool {
        self.sequence1 == self.sequence2 && self.sequence1 != 0
    }

    /// 主版本 / 次版本。
    pub fn version(&self) -> String {
        format!("{}.{}", self.major, self.minor)
    }
}

/// 按 regf 规范计算 base block 校验和：0x00..0x1fb 的 127 个 u32 字异或。
///
/// 注意 0x1fc 的校验和字段**不在**异或范围内，所以对同一份头部调用两次结果相同。
pub fn compute_checksum(head: &[u8]) -> u32 {
    let mut checksum = 0_u32;
    let mut at = 0;
    while at + 4 <= 0x1fc {
        match rd_u32(head, at) {
            Some(word) => checksum ^= word,
            None => break,
        }
        at += 4;
    }
    checksum
}

// ---------------------------------------------------------------------------
// 子键列表
// ---------------------------------------------------------------------------

/// 子键列表单元签名。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubkeyListKind {
    /// `lf`（4 字节名字 hash）
    Lf,
    /// `lh`（4 字节名字 hash）
    Lh,
    /// `li`（仅偏移）
    Li,
    /// `ri`（指向子列表）
    Ri,
}

impl SubkeyListKind {
    fn from_signature(signature: &[u8]) -> Option<Self> {
        match signature {
            b"lf" => Some(Self::Lf),
            b"lh" => Some(Self::Lh),
            b"li" => Some(Self::Li),
            b"ri" => Some(Self::Ri),
            _ => None,
        }
    }

    /// 每个条目占用的字节数。
    pub fn entry_size(self) -> usize {
        match self {
            Self::Lf | Self::Lh => 8,
            Self::Li | Self::Ri => 4,
        }
    }

    #[allow(dead_code)]
    pub fn name(self) -> &'static str {
        match self {
            Self::Lf => "lf",
            Self::Lh => "lh",
            Self::Li => "li",
            Self::Ri => "ri",
        }
    }
}

/// 一个键节点（`nk`）的解析结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyNode {
    pub cell_offset: u32,
    pub name: String,
    /// 0x02 的 flags 原值（0x20 = ASCII/压缩键名）。
    pub flags: u16,
    pub compressed_name: bool,
    /// 0x04 last write（FILETIME 原值）。
    pub last_write_raw: u64,
    /// 0x14 子键数。
    pub subkey_count: u32,
    /// 0x1c 子键列表偏移（无子键时为 `NO_CELL`）。
    pub subkey_list: u32,
    /// 0x20 volatile 子键数（常为 0xFFFFFFFF）。
    pub volatile_subkey_count: u32,
    /// 0x24 值数。
    pub value_count: u32,
    /// 0x28 值列表偏移（无值时为 `NO_CELL`）。
    pub value_list: u32,
    /// 0x48 声明的键名长度。
    pub name_len: u16,
    /// 0x4a 类名长度。
    pub class_len: u16,
}

impl KeyNode {
    pub fn has_subkeys(&self) -> bool {
        self.subkey_count > 0 && self.subkey_list != NO_CELL
    }

    pub fn has_values(&self) -> bool {
        self.value_count > 0 && self.value_list != NO_CELL
    }
}

// ---------------------------------------------------------------------------
// cell 定位
// ---------------------------------------------------------------------------

/// 已定位 cell 的几何信息。
#[derive(Clone, Debug, PartialEq, Eq)]
struct CellLocation {
    /// cell 头（长度前缀）的文件内偏移。
    start: u64,
    /// 载荷的文件内偏移。
    payload_start: u64,
    /// 载荷长度（不含 4 字节前缀）。
    payload_len: usize,
    /// 长度前缀为负（已分配）。
    allocated: bool,
    /// 载荷首 2 字节（签名）。
    signature: [u8; 2],
}

// ---------------------------------------------------------------------------
// Hive
// ---------------------------------------------------------------------------

/// 打开一次 hive 的解析器。所有方法只读。
pub struct Hive<S: ReadAt> {
    source: S,
    size: u64,
    header: BaseBlock,
    bins_end: u64,
}

impl<S: ReadAt> Hive<S> {
    /// 校验 base block 并打开 hive。
    ///
    /// 校验顺序（任一项不通过都不解析，返回带偏移的错误）：
    /// 文件长度 ≥ 0x1000 → 魔数 `regf` → major/minor 版本 → 文件类型为 0（非事务日志）
    /// → 0x1000 处为 `hbin` → 头部声明的 bins 长度是 0x1000 的正整数倍且不超过文件长度
    /// → checksum 与计算值一致（存储值 0 视为“未写入”，放行）。
    ///
    /// 序列号不一致不阻断解析（由调用方在报告里提示“可能部分写”）。
    pub fn open(source: S) -> Res<Self> {
        let size = source.size();
        if size < BASE_BLOCK_SIZE + MIN_HBIN_SIZE as u64 {
            return Err(HiveError::new(
                ErrorKind::BadSignature,
                0,
                format!(
                    "文件只有 {size} 字节，不足 regf 头（0x1000）+ 一个 hbin（0x1000）（截断或不是 hive）"
                ),
            ));
        }
        let head = read_exact(&source, 0, BASE_BLOCK_SIZE as usize)
            .map_err(|detail| HiveError::new(ErrorKind::Read, 0, format!("读取 regf 头失败: {detail}")))?;
        if &head[0..4] != b"regf" {
            return Err(HiveError::new(
                ErrorKind::BadSignature,
                0,
                format!("魔数不是 regf（实际 {}）", escaped_hex(&head[0..4])),
            ));
        }
        let major = rd_u32(&head, 0x14).unwrap_or(0);
        let minor = rd_u32(&head, 0x18).unwrap_or(0);
        if major != 1 || minor > 6 {
            return Err(HiveError::new(
                ErrorKind::Corrupt,
                0x14,
                format!("不支持的 hive 版本 {major}.{minor}（本解析器仅支持 1.1 ~ 1.6）"),
            ));
        }
        let file_type = rd_u32(&head, 0x1c).unwrap_or(0);
        if file_type != 0 {
            return Err(HiveError::new(
                ErrorKind::LogHeader,
                0x1c,
                format!("文件类型为 {file_type}（事务日志），不是主 hive，拒绝解析"),
            ));
        }
        // 首个 hbin 块紧跟 0x1000 字节的 base block，其块头（"hbin"）就在文件偏移 0x1000。
        // 注意：`head` 只有 0x1000 字节，必须另行读取这一处 4 字节。
        match read_exact(&source, BASE_BLOCK_SIZE, 4) {
            Ok(signature) if signature.as_slice() == b"hbin" => {}
            Ok(signature) => {
                return Err(HiveError::new(
                    ErrorKind::BadSignature,
                    0x1000,
                    format!(
                        "0x1000 处不是 hbin 块（读到 {}），base block 被截断或布局异常",
                        escaped_hex(&signature)
                    ),
                ));
            }
            Err(detail) => {
                return Err(HiveError::new(
                    ErrorKind::BadSignature,
                    0x1000,
                    format!("0x1000 处读不到 hbin 块头（base block 被截断）：{detail}"),
                ));
            }
        }
        let hbins_size = rd_u32(&head, 0x28).unwrap_or(0);
        if hbins_size == 0 || hbins_size % MIN_HBIN_SIZE != 0 {
            return Err(HiveError::new(
                ErrorKind::Corrupt,
                0x28,
                format!("头部声明 hive bins 数据长度 0x{hbins_size:x}，不是 0x1000 的正整数倍"),
            ));
        }
        let bins_end = BASE_BLOCK_SIZE + u64::from(hbins_size);
        if bins_end > size {
            return Err(HiveError::new(
                ErrorKind::Corrupt,
                0x28,
                format!(
                    "头部声明 hive bins 数据长度 0x{hbins_size:x}，需要文件至少 0x{bins_end:x} 字节，实际只有 0x{size:x} 字节（截断）"
                ),
            ));
        }
        let header = BaseBlock {
            sequence1: rd_u32(&head, 0x04).unwrap_or(0),
            sequence2: rd_u32(&head, 0x08).unwrap_or(0),
            last_write_raw: rd_u64(&head, 0x0c).unwrap_or(0),
            major,
            minor,
            file_type,
            file_format: rd_u32(&head, 0x20).unwrap_or(0),
            root_cell_offset: rd_u32(&head, 0x24).unwrap_or(NO_CELL),
            hbins_size,
            clustering: rd_u32(&head, 0x2c).unwrap_or(0),
            file_name: decode_hive_file_name(&head),
            checksum: rd_u32(&head, 0x1fc).unwrap_or(0),
            computed_checksum: compute_checksum(&head),
        };
        if !header.checksum_ok() {
            return Err(HiveError::new(
                ErrorKind::Corrupt,
                0x1fc,
                format!(
                    "base block 校验和不一致：存储 0x{:08x}，计算 0x{:08x}",
                    header.checksum, header.computed_checksum
                ),
            ));
        }
        Ok(Self {
            source,
            size,
            header,
            bins_end,
        })
    }

    pub fn header(&self) -> &BaseBlock {
        &self.header
    }

    pub fn file_size(&self) -> u64 {
        self.size
    }

    pub fn source(&self) -> &S {
        &self.source
    }

    /// hive bins 数据区的文件内结束偏移。
    pub fn bins_end(&self) -> u64 {
        self.bins_end
    }

    /// 开发期诊断：按任意解释定位一个单元并返回几何信息。
    pub fn debug_cell(&self, offset: u32) -> Option<(u64, usize, String, String)> {
        match self.locate_cell(offset, &[], "诊断") {
            Ok(cell) => Some((
                cell.start,
                cell.payload_len,
                escaped_hex(&cell.signature),
                hex_bytes(&self.read(cell.payload_start, cell.payload_len.min(32)).ok()?),
            )),
            Err(error) => Some((0, 0, error.kind.code().to_owned(), error.detail)),
        }
    }

    fn read(&self, offset: u64, length: usize) -> Res<Vec<u8>> {
        if length == 0 {
            return Ok(Vec::new());
        }
        let end = offset.saturating_add(length as u64);
        if end > self.size {
            return Err(HiveError::new(
                ErrorKind::OutOfBounds,
                offset,
                format!("读取 [0x{offset:x},0x{end:x}) 超出文件长度 0x{:x}", self.size),
            ));
        }
        read_exact(&self.source, offset, length).map_err(|detail| {
            HiveError::new(
                ErrorKind::Read,
                offset,
                format!("读取 0x{length:x} 字节失败: {detail}"),
            )
        })
    }

    /// 定位一个带 4 字节长度前缀的 cell，并校验其签名属于 `expected`
    /// （`expected` 为空表示任意签名都接受，但长度前缀仍必须合法）。
    fn locate_cell(&self, offset: u32, expected: &[&[u8; 2]], label: &str) -> Res<CellLocation> {
        if offset == NO_CELL {
            return Err(HiveError::new(
                ErrorKind::OutOfBounds,
                BASE_BLOCK_SIZE,
                format!("{label}偏移是空单元哨兵 0xFFFFFFFF"),
            ));
        }
        let start = BASE_BLOCK_SIZE + u64::from(offset);
        if start < BASE_BLOCK_SIZE + 4 || start + 8 > self.bins_end {
            return Err(HiveError::new(
                ErrorKind::OutOfBounds,
                start,
                format!(
                    "{label}偏移 0x{offset:x} 落在 hive bins 数据区 [0x1000,0x{:x}) 之外",
                    self.bins_end
                ),
            ));
        }
        let prefix = self.read(start, 4)?;
        let size = rd_i32(&prefix, 0).unwrap_or(0);
        let magnitude = size.unsigned_abs();
        if magnitude < 8 || magnitude > MAX_CELL_SIZE {
            return Err(HiveError::new(
                ErrorKind::OutOfBounds,
                start,
                format!("{label}偏移 0x{offset:x} 处没有合法的 cell 长度前缀（读到 {size}）"),
            ));
        }
        let cell_end = start + u64::from(magnitude);
        if cell_end > self.bins_end {
            return Err(HiveError::new(
                ErrorKind::OutOfBounds,
                start,
                format!(
                    "{label}偏移 0x{offset:x} 的 cell 长度 {magnitude} 越过 hive bins 数据区末尾 0x{:x}",
                    self.bins_end
                ),
            ));
        }
        let head = self.read(start + 4, 2)?;
        let signature = [head[0], head[1]];
        if !expected.is_empty() && !expected.iter().any(|sig| **sig == signature) {
            return Err(HiveError::new(
                ErrorKind::OutOfBounds,
                start + 4,
                format!(
                    "{label}偏移 0x{offset:x} 处的 cell 签名是 {}，与预期（{}）不符",
                    escaped_hex(&signature),
                    expected
                        .iter()
                        .map(|sig| escaped_hex(*sig))
                        .collect::<Vec<_>>()
                        .join("/")
                ),
            ));
        }
        // 归属校验：cell 起点必须落在 hbin 内并 8 字节对齐；长度前缀必须落在
        // 8..=256 MiB（上面已校验）且不越过 hive bins 数据区末尾（上面已校验）。
        // 不要求“前一个 cell 的长度正好衔接”：缺损 / 重新打包过的 hive 上这条性质
        // 并不总成立，用它会把合法 hive 误判为损坏；越界由长度与签名两处把关。
        let relative = start - BASE_BLOCK_SIZE;
        let bin_relative = relative % u64::from(MIN_HBIN_SIZE);
        if bin_relative % 8 != 0 || (bin_relative > 0 && bin_relative < MIN_HBIN_HEADER) {
            return Err(HiveError::new(
                ErrorKind::OutOfBounds,
                start,
                format!("{label}偏移 0x{offset:x} 在 hbin 内没有 8 字节对齐"),
            ));
        }
        Ok(CellLocation {
            start,
            payload_start: start + 4,
            payload_len: magnitude as usize - 4,
            allocated: size < 0,
            signature,
        })
    }

    /// 读一个 `nk` 键节点。`offset` 可以是“带前缀的 cell 偏移”，也可以是
    /// “相对首个 hbin 的载荷位置”（根键用后者）。
    pub fn read_key(&self, offset: u32) -> Res<KeyNode> {
        let cell = match self.locate_cell(offset, &[b"nk"], "键单元") {
            Ok(cell) => cell,
            Err(primary) => {
                if let Some(cell) = self.locate_payload_cell(offset, Some(b"nk"))? {
                    cell
                } else {
                    return Err(primary);
                }
            }
        };
        let payload = self.read(cell.payload_start, 0x4c.min(cell.payload_len))?;
        if payload.len() < 0x4c {
            return Err(HiveError::new(
                ErrorKind::Corrupt,
                cell.payload_start,
                format!("nk 载荷只有 {} 字节，小于 0x4c", payload.len()),
            ));
        }
        let flags = rd_u16(&payload, 0x02).unwrap_or(0);
        let compressed = flags & KEY_COMP_NAME != 0;
        let name_len = rd_u16(&payload, 0x48).unwrap_or(0);
        let class_len = rd_u16(&payload, 0x4a).unwrap_or(0);
        let name = self.read_key_name(&cell, compressed, name_len)?;
        Ok(KeyNode {
            cell_offset: offset,
            name,
            flags,
            compressed_name: compressed,
            last_write_raw: rd_u64(&payload, 0x04).unwrap_or(0),
            subkey_count: rd_u32(&payload, 0x14).unwrap_or(0),
            subkey_list: rd_u32(&payload, 0x1c).unwrap_or(NO_CELL),
            volatile_subkey_count: rd_u32(&payload, 0x20).unwrap_or(0),
            value_count: rd_u32(&payload, 0x24).unwrap_or(0),
            value_list: rd_u32(&payload, 0x28).unwrap_or(NO_CELL),
            name_len,
            class_len,
        })
    }

    /// 以“偏移本身就是载荷位置”的解释定位一个 nk（根键偏移的语义）。
    fn locate_payload_cell(
        &self,
        offset: u32,
        signature: Option<&[u8; 2]>,
    ) -> Res<Option<CellLocation>> {
        if offset == NO_CELL {
            return Ok(None);
        }
        let payload_start = BASE_BLOCK_SIZE + u64::from(offset);
        if payload_start < BASE_BLOCK_SIZE || payload_start + 4 > self.bins_end {
            return Ok(None);
        }
        let head = match self.read(payload_start, 4) {
            Ok(head) => head,
            Err(_) => return Ok(None),
        };
        if let Some(signature) = signature {
            if head[0] != signature[0] || head[1] != signature[1] {
                return Ok(None);
            }
        }
        // 载荷长度取到本 hbin 末尾（cell 长度前缀不在载荷之前的这个解释里可信）。
        let bin_end = (payload_start - BASE_BLOCK_SIZE) / MIN_HBIN_SIZE as u64 * MIN_HBIN_SIZE as u64
            + BASE_BLOCK_SIZE
            + MIN_HBIN_SIZE as u64;
        let payload_len = (bin_end.min(self.bins_end) - payload_start) as usize;
        Ok(Some(CellLocation {
            start: payload_start - 4,
            payload_start,
            payload_len,
            allocated: true,
            signature: [head[0], head[1]],
        }))
    }

    /// 键名：压缩（0x20）时内联在 0x4c；否则 0x4c 处是 UTF-16LE 名字单元偏移。
    fn read_key_name(&self, cell: &CellLocation, compressed: bool, name_len: u16) -> Res<String> {
        if name_len == 0 {
            return Ok(String::new());
        }
        let name_len = usize::from(name_len);
        if name_len > 0x1_0000 {
            return Err(HiveError::new(
                ErrorKind::Corrupt,
                cell.payload_start + 0x48,
                format!("键名长度 {name_len} 不合理"),
            ));
        }
        // 名称可能内联在 nk 尾部（少数工具），也可能放在独立名称单元里（Windows 的写法）。
        // 只在“名称单元”解释失败时才退回内联，保证两种布局都能读。
        let inline_at = cell.payload_start + 0x4c;
        let pointer = self.read(inline_at, 4)?;
        let name_offset = rd_u32(&pointer, 0).unwrap_or(NO_CELL);
        let relative = self.locate_payload_cell(name_offset, None).ok().flatten();
        let name_cell = match self.locate_cell(name_offset, &[], "键名单元") {
            Ok(name_cell) => Some(name_cell),
            Err(_) => relative,
        };
        let Some(name_cell) = name_cell else {
            // 内联：0x4c 起就是名称数据本身。
            let want = match compressed {
                true => name_len,
                false => name_len * 2,
            };
            if 0x4c + want > cell.payload_len {
                return Err(HiveError::new(
                    ErrorKind::OutOfBounds,
                    inline_at,
                    format!("nk 载荷 {} 字节放不下 {want} 字节内联键名", cell.payload_len),
                ));
            }
            let raw = self.read(inline_at, want)?;
            let name = match compressed {
                true => decode_compressed_name(&raw),
                false => decode_utf16le(&raw),
            };
            return Ok(trim_name_terminator(&name).to_owned());
        };
        // nk 的 0x48 字段是「名称字符数（含结尾 NUL 字符）」；压缩名 1 字节/字符。
        let mut bytes_len = match compressed {
            true => name_len,
            false => name_len * 2,
        };
        // 少数工具把该字段写成字节数：当 2×len 放不下而 len 恰好放得下时按字节数读。
        if bytes_len > name_cell.payload_len && name_len <= name_cell.payload_len {
            bytes_len = name_len;
        }
        if bytes_len > name_cell.payload_len {
            return Err(HiveError::new(
                ErrorKind::OutOfBounds,
                name_cell.payload_start,
                format!(
                    "键名单元 {} 字节放不下 {bytes_len} 字节键名（压缩名={compressed}）",
                    name_cell.payload_len
                ),
            ));
        }
        let raw = self.read(name_cell.payload_start, bytes_len)?;
        let name = match compressed {
            true => decode_compressed_name(&raw),
            false => decode_utf16le(&raw),
        };
        Ok(trim_name_terminator(&name).to_owned())
    }

    /// 子键列表（展开 `ri`），返回 `(cell 偏移, 键名)`。
    pub fn subkey_entries(&self, key: &KeyNode) -> Res<Vec<(u32, String)>> {
        if !key.has_subkeys() {
            return Ok(Vec::new());
        }
        let offsets = self.expand_subkey_list(key.subkey_list, key.subkey_count, 0)?;
        let mut entries = Vec::with_capacity(offsets.len());
        let mut error: Option<HiveError> = None;
        for offset in offsets {
            match self.read_key(offset) {
                Ok(child) => entries.push((offset, child.name)),
                // 单个子键损坏不放弃整个列表：记录首个错误，继续。
                Err(failure) => {
                    if error.is_none() {
                        error = Some(failure);
                    }
                }
            }
        }
        if entries.is_empty() {
            if let Some(error) = error {
                return Err(error);
            }
        }
        Ok(entries)
    }

    /// 子键列表条目解析失败时返回的原因（供报告记录）。
    pub fn subkey_entries_tolerant(&self, key: &KeyNode) -> (Vec<(u32, String)>, Vec<HiveError>) {
        let mut errors = Vec::new();
        let mut entries = Vec::new();
        if !key.has_subkeys() {
            return (entries, errors);
        }
        let offsets = match self.expand_subkey_list(key.subkey_list, key.subkey_count, 0) {
            Ok(offsets) => offsets,
            Err(error) => {
                errors.push(error);
                return (entries, errors);
            }
        };
        for offset in offsets {
            match self.read_key(offset) {
                Ok(child) => entries.push((offset, child.name)),
                Err(failure) => errors.push(failure),
            }
        }
        (entries, errors)
    }

    fn expand_subkey_list(&self, offset: u32, limit: u32, depth: usize) -> Res<Vec<u32>> {
        if depth > MAX_RI_DEPTH {
            return Err(HiveError::new(
                ErrorKind::ResourceLimit,
                BASE_BLOCK_SIZE + u64::from(offset),
                format!("ri 子键索引嵌套超过 {MAX_RI_DEPTH} 层"),
            ));
        }
        let cell = self.locate_cell(offset, &[b"lf", b"lh", b"li", b"ri"], "子键列表单元")?;
        if !matches!(
            cell.signature,
            [b'l', _] | [b'r', b'i']
        ) {
            return Err(HiveError::new(
                ErrorKind::OutOfBounds,
                cell.payload_start,
                "未知子键列表签名",
            ));
        }
        let kind = SubkeyListKind::from_signature(&cell.signature).ok_or_else(|| {
            HiveError::new(
                ErrorKind::OutOfBounds,
                cell.payload_start,
                "未知子键列表签名",
            )
        })?;
        // 载荷布局：0x00 签名、0x02 条目数（u16）、0x04 起为条目。
        // 条目 = 4 字节子键偏移 [+ lf/lh 的 4 字节名字哈希]。
        let header = self.read(cell.payload_start, 4)?;
        let declared = usize::from(rd_u16(&header, 2).unwrap_or(0));
        let entries_at = cell.payload_start + 4;
        let available = cell.payload_len.saturating_sub(4) / kind.entry_size();
        let capacity_limit = if limit == 0 {
            MAX_LIST_ENTRIES
        } else {
            (limit as usize).min(MAX_LIST_ENTRIES)
        };
        let take = declared.min(available).min(capacity_limit);
        let raw = self.read(entries_at, take * kind.entry_size())?;
        let mut offsets = Vec::with_capacity(take);
        for index in 0..take {
            let entry = &raw[index * kind.entry_size()..];
            let Some(value) = rd_u32(entry, 0) else {
                break;
            };
            if kind == SubkeyListKind::Ri {
                let nested = self.expand_subkey_list(value, 0, depth + 1)?;
                if offsets.len() + nested.len() > MAX_LIST_ENTRIES {
                    return Err(HiveError::new(
                        ErrorKind::ResourceLimit,
                        cell.payload_start,
                        format!("子键条目超过 {MAX_LIST_ENTRIES}"),
                    ));
                }
                offsets.extend(nested);
            } else {
                offsets.push(value);
            }
        }
        Ok(offsets)
    }

    /// 键的值列表里的 `vk` 偏移。
    pub fn value_offsets(&self, key: &KeyNode) -> Res<Vec<u32>> {
        if !key.has_values() {
            return Ok(Vec::new());
        }
        let cell = self.locate_cell(key.value_list, &[], "值列表单元")?;
        if key.value_count as usize > MAX_LIST_ENTRIES {
            return Err(HiveError::new(
                ErrorKind::ResourceLimit,
                cell.payload_start,
                format!("键声明 {} 个值，超过上限 {MAX_LIST_ENTRIES}", key.value_count),
            ));
        }
        let count = (key.value_count as usize).min(cell.payload_len / 4);
        let raw = self.read(cell.payload_start, count * 4)?;
        let mut offsets = Vec::with_capacity(count);
        for index in 0..count {
            match rd_u32(&raw, index * 4) {
                Some(offset) => offsets.push(offset),
                None => break,
            }
        }
        Ok(offsets)
    }

    /// 读一个 `vk` 值节点（含内联数据与 `db` 大值）。
    pub fn read_value(&self, offset: u32) -> Res<HiveValue> {
        let cell = self.locate_cell(offset, &[b"vk"], "值单元")?;
        let payload = self.read(cell.payload_start, 0x14.min(cell.payload_len))?;
        if payload.len() < 0x14 {
            return Err(HiveError::new(
                ErrorKind::Corrupt,
                cell.payload_start,
                format!("vk 载荷只有 {} 字节，小于 0x14", payload.len()),
            ));
        }
        let name_len = usize::from(rd_u16(&payload, 0x02).unwrap_or(0));
        let declared_len = rd_u32(&payload, 0x04).unwrap_or(0);
        let data_offset = rd_u32(&payload, 0x08).unwrap_or(0);
        let raw_type = rd_u32(&payload, 0x0c).unwrap_or(0);
        let flags = rd_u16(&payload, 0x10).unwrap_or(0);
        let inline = declared_len & VALUE_INLINE_DATA != 0;
        let declared = declared_len & !VALUE_INLINE_DATA;
        if declared > MAX_VALUE_BYTES {
            return Err(HiveError::new(
                ErrorKind::ResourceLimit,
                cell.payload_start + 0x04,
                format!("值数据长度 {declared} 超过上限 {MAX_VALUE_BYTES}"),
            ));
        }
        // 值名长度字段是“名称数据字节数（含结尾 NUL 字符）”：UTF-16 名 = 2n+2，
        // 压缩名（VALUE_COMP_NAME）= n+1。两种 hive 都只写其一，这里按标志位换算，
        // 并对照载荷实际剩余字节数做越界保护。
        let compressed = flags & VALUE_COMP_NAME != 0;
        let terminator = if compressed { 1 } else { 2 };
        let name_bytes = usize::from(name_len).saturating_sub(terminator);
        let name = if name_bytes == 0 {
            String::new()
        } else if cell.payload_len.saturating_sub(0x14) >= name_bytes {
            let raw = self.read(cell.payload_start + 0x14, name_bytes)?;
            if compressed {
                decode_compressed_name(&raw)
            } else {
                decode_utf16le(&raw)
            }
        } else {
            return Err(HiveError::new(
                ErrorKind::OutOfBounds,
                cell.payload_start + 0x14,
                format!(
                    "vk 载荷 {} 字节放不下 {name_bytes} 字节值名（长度字段 {name_len}，压缩名={compressed}）",
                    cell.payload_len
                ),
            ));
        };
        let want = usize::try_from(declared).unwrap_or(usize::MAX);
        let fetched = self.value_bytes(offset, &cell, data_offset, want, inline)?;
        let value_type = ValueType::from_raw(raw_type);
        let data = decode_value(value_type, &fetched.bytes);
        Ok(HiveValue {
            name,
            value_type,
            raw_type,
            flags,
            declared_len: declared,
            inline,
            big_data: fetched.big_data,
            data_cell: fetched.data_cell,
            vk_cell: offset,
            raw_hex: hex_bytes(&fetched.bytes),
            data,
            raw_len: fetched.bytes.len(),
            truncated: fetched.bytes.len() < want,
        })
    }

    fn value_bytes(
        &self,
        vk_offset: u32,
        cell: &CellLocation,
        data_offset: u32,
        want: usize,
        inline: bool,
    ) -> Res<Fetched> {
        let empty = Fetched {
            bytes: Vec::new(),
            big_data: false,
            data_cell: NO_CELL,
        };
        if want == 0 {
            return Ok(empty);
        }
        if inline {
            // 内联：数据就在 vk 的 0x08..0x0c 四字节里（最多 4 字节）。
            // 注意 0x08 字段同时也是「数据偏移」，所以这里按声明长度截断，
            // 不能把 4 字节整体当数据（声明 2 字节时只看前 2 字节）。
            if cell.payload_len < 0x0c {
                return Err(HiveError::new(
                    ErrorKind::OutOfBounds,
                    cell.payload_start + 0x08,
                    "内联值数据超出 vk 载荷",
                ));
            }
            let raw = self.read(cell.payload_start + 0x08, 4)?;
            let take = want.min(4);
            return Ok(Fetched {
                bytes: raw[..take].to_vec(),
                big_data: false,
                data_cell: NO_CELL,
            });
        }
        if data_offset == NO_CELL {
            return Err(HiveError::new(
                ErrorKind::Corrupt,
                cell.payload_start + 0x08,
                format!(
                    "值数据未内联（声明长度 {want}）但数据偏移是空单元哨兵 0xFFFFFFFF（vk@0x{vk_offset:x}）"
                ),
            ));
        }
        let data_cell = self.locate_cell(data_offset, &[], "值数据单元")?;
        let head = self.read(data_cell.payload_start, 2.min(data_cell.payload_len))?;
        if head.as_slice() == b"db" {
            let bytes = self.read_big_data(data_offset, want)?;
            return Ok(Fetched {
                bytes,
                big_data: true,
                data_cell: data_offset,
            });
        }
        let take = want.min(data_cell.payload_len);
        Ok(Fetched {
            bytes: self.read(data_cell.payload_start, take)?,
            big_data: false,
            data_cell: data_offset,
        })
    }

    /// `db` 大值：段列表单元里是若干分段单元偏移，各段载荷依次拼接即为值数据。
    fn read_big_data(&self, db_offset: u32, want: usize) -> Res<Vec<u8>> {
        let cell = self.locate_cell(db_offset, &[b"db"], "大值单元")?;
        let header = self.read(cell.payload_start, 4.min(cell.payload_len))?;
        if header.len() < 4 {
            return Err(HiveError::new(
                ErrorKind::Corrupt,
                cell.payload_start,
                "db 大值头不足 4 字节",
            ));
        }
        let segments = usize::from(rd_u16(&header, 2).unwrap_or(0));
        // db 头：0x00 "db"、0x02 段数、0x04 段列表偏移（载荷 +4 起 4 字节）。
        let list_offset = match cell.payload_len >= 8 {
            true => rd_u32(&self.read(cell.payload_start, 8)?, 4).unwrap_or(NO_CELL),
            false => NO_CELL,
        };
        if segments == 0 || segments > 0x4000 {
            return Err(HiveError::new(
                ErrorKind::Corrupt,
                cell.payload_start,
                format!("db 分段数 {segments} 非法"),
            ));
        }
        let list_cell = self.locate_cell(list_offset, &[], "大值段列表单元")?;
        if list_cell.payload_len / 4 < segments {
            return Err(HiveError::new(
                ErrorKind::Corrupt,
                list_cell.payload_start,
                format!(
                    "大值段列表单元 {} 字节放不下 {segments} 个分段偏移",
                    list_cell.payload_len
                ),
            ));
        }
        let raw = self.read(list_cell.payload_start, segments * 4)?;
        let mut out = Vec::with_capacity(want.min(MAX_VALUE_BYTES as usize));
        for index in 0..segments {
            let Some(segment_offset) = rd_u32(&raw, index * 4) else {
                break;
            };
            let segment = self.locate_cell(segment_offset, &[], "大值分段单元")?;
            if segment.payload_len as u64 > u64::from(MAX_BIG_SEGMENT) * 2 {
                return Err(HiveError::new(
                    ErrorKind::ResourceLimit,
                    segment.payload_start,
                    format!("大值分段 {} 字节超过上限", segment.payload_len),
                ));
            }
            let take = segment
                .payload_len
                .min(want.saturating_sub(out.len()).max(1));
            let chunk = self.read(segment.payload_start, take)?;
            out.extend_from_slice(&chunk);
            if out.len() >= want {
                break;
            }
        }
        out.truncate(want);
        Ok(out)
    }

    /// 读根键。
    pub fn root_key(&self) -> Res<KeyNode> {
        self.read_key(self.header.root_cell_offset)
    }

    /// 按键名（大小写不敏感，Unicode 简单大小写折叠后的 ASCII 比较）查子键，
    /// 同时收集子键列表里的读取错误。
    pub fn lookup_subkey_all(
        &self,
        parent: &KeyNode,
        name: &str,
    ) -> (Vec<KeyNode>, Vec<HiveError>) {
        let (entries, mut errors) = self.subkey_entries_tolerant(parent);
        let mut matches = Vec::new();
        for (offset, child_name) in entries {
            if names_equal(&child_name, name) {
                match self.read_key(offset) {
                    Ok(child) => matches.push(child),
                    Err(error) => errors.push(error),
                }
            }
        }
        (matches, errors)
    }

    /// 按路径（段名大小写不敏感）逐层查找，返回 `(命中, 第一个缺失段, 警告)`。
    ///
    /// `segments` 为空表示根键本身。
    pub fn lookup_path_verbose(&self, segments: &[&str]) -> Res<PathLookup> {
        if segments.len() > MAX_PATH_DEPTH {
            return Err(HiveError::new(
                ErrorKind::ResourceLimit,
                BASE_BLOCK_SIZE,
                format!("键路径深度 {} 超过上限 {MAX_PATH_DEPTH}", segments.len()),
            ));
        }
        let mut warnings = Vec::new();
        let mut current = self.root_key()?;
        let mut resolved = Vec::new();
        for segment in segments {
            let (matches, errors) = self.lookup_subkey_all(&current, segment);
            warnings.extend(errors);
            if matches.is_empty() {
                return Ok(PathLookup {
                    key: None,
                    resolved_path: segments[..resolved.len()].join("\\"),
                    missing_segment: Some((*segment).to_owned()),
                    warnings,
                });
            }
            if matches.len() > 1 {
                warnings.push(self.pick_first_match(
                    current.cell_offset,
                    &current.name,
                    segment,
                    matches.len(),
                ));
            }
            resolved.push(matches[0].name.clone());
            current = matches[0].clone();
        }
        Ok(PathLookup {
            resolved_path: resolved.join("\\"),
            key: Some(current),
            missing_segment: None,
            warnings,
        })
    }
    /// 子键名等价但大小写不同的父键下取第一个，并记录原因。
    fn pick_first_match(&self, offset: u32, label: &str, segment: &str, count: usize) -> HiveError {
        let _ = label;
        HiveError::new(
            ErrorKind::Corrupt,
            BASE_BLOCK_SIZE + u64::from(offset),
            format!("同一父键下有 {count} 个大小写不同但等价于「{segment}」的子键名"),
        )
    }
}
/// 路径查找结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PathLookup {
    /// 实际枚举到的键名拼成的路径（保留原始大小写）。
    pub resolved_path: String,
    pub key: Option<KeyNode>,
    /// 第一个找不到的路径段。
    pub missing_segment: Option<String>,
    pub warnings: Vec<HiveError>,
}

struct Fetched {
    bytes: Vec<u8>,
    big_data: bool,
    data_cell: u32,
}

/// 大小写不敏感的名字比较：ASCII 折叠 + 逐字符（含非 ASCII 简单折叠）比较。
pub fn names_equal(left: &str, right: &str) -> bool {
    left.chars()
        .map(simple_fold)
        .eq(right.chars().map(simple_fold))
}

fn simple_fold(character: char) -> char {
    if character.is_ascii() {
        character.to_ascii_lowercase()
    } else {
        let mut lower = character.to_lowercase();
        match (lower.next(), lower.next()) {
            (Some(single), None) => single,
            _ => character,
        }
    }
}

fn read_exact<S: ReadAt>(
    source: &S,
    offset: u64,
    length: usize,
) -> std::result::Result<Vec<u8>, String> {
    let bytes = source.read_at(offset, length)?;
    if bytes.len() != length {
        return Err(format!(
            "短读: 0x{offset:x} 处需要 {length} 字节，实际 {} 字节",
            bytes.len()
        ));
    }
    Ok(bytes)
}

/// UTF-16LE → String（奇数尾字节忽略，孤立代理项替换为 U+FFFD）。
pub fn decode_utf16le(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16_lossy(&units)
}

/// 压缩键名/值名：逐字节按 Latin-1 提升为码点（0x00..0xFF → U+0000..U+00FF）。
pub fn decode_compressed_name(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(*byte)).collect()
}

/// 去掉键名/值名结尾的 NUL 字符（长度字段含结尾 NUL，键名单元里也常带着它）。
pub fn trim_name_terminator(name: &str) -> &str {
    name.trim_end_matches('\0')
}

fn decode_value(value_type: ValueType, raw: &[u8]) -> ValueData {
    match value_type {
        ValueType::Dword => match rd_u32(raw, 0) {
            Some(value) => ValueData::Dword(value),
            None => ValueData::Bytes(raw.to_vec()),
        },
        ValueType::DwordBigEndian => match raw.get(0..4) {
            Some(slice) => ValueData::Dword(u32::from_be_bytes([slice[0], slice[1], slice[2], slice[3]])),
            None => ValueData::Bytes(raw.to_vec()),
        },
        ValueType::Qword => match rd_u64(raw, 0) {
            Some(value) => ValueData::Qword(value),
            None => ValueData::Bytes(raw.to_vec()),
        },
        ValueType::Sz | ValueType::ExpandSz | ValueType::Link => {
            ValueData::Text(decode_utf16le(raw))
        }
        ValueType::MultiSz => ValueData::Text(decode_multi_sz(raw)),
        ValueType::None | ValueType::Binary | ValueType::Other(_) => ValueData::Bytes(raw.to_vec()),
    }
}

/// REG_MULTI_SZ：UTF-16LE 字符串序列，以空字符串结束；用 `\n` 连接。
pub fn decode_multi_sz(raw: &[u8]) -> String {
    let text = decode_utf16le(raw);
    let mut parts: Vec<&str> = text.split('\0').collect();
    while parts.last().is_some_and(|part| part.is_empty()) {
        parts.pop();
    }
    parts.join("\n")
}

/// 十六进制展示（最多 64 字节，超出部分标注）。
pub fn hex_bytes(bytes: &[u8]) -> String {
    const LIMIT: usize = 64;
    let shown = bytes.len().min(LIMIT);
    let mut text = bytes[..shown]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    if bytes.len() > shown {
        text.push_str(&format!(" …(+{} 字节)", bytes.len() - shown));
    }
    if text.is_empty() {
        text.push_str("(空)");
    }
    text
}

fn escaped_hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "(空)".to_owned();
    }
    bytes
        .iter()
        .map(|byte| {
            if byte.is_ascii_graphic() {
                (*byte as char).to_string()
            } else {
                format!("\\x{byte:02x}")
            }
        })
        .collect()
}

/// 从文件头取 hive 文件名（`0x30` 起 64 字节 UTF-16LE）。
fn decode_hive_file_name(head: &[u8]) -> String {
    let raw = head.get(0x30..0x70).unwrap_or(&[]);
    let text = decode_utf16le(raw);
    text.trim_end_matches('\0').trim().to_owned()
}

/// 头部 last write 为 0 / 不可换算时的展示文本。
pub fn filetime_unused_marker(raw: u64) -> String {
    if raw == 0 {
        "(原值 0，Windows 常以此表示未写入)".to_owned()
    } else {
        format!("(原值 {raw} 不可换算为 1601 年以后的时间)")
    }
}

/// 值偏移列表（公开包装，供报告列出目标键下的值名）。
#[allow(dead_code)]
pub fn list_value_offsets<S: ReadAt>(hive: &Hive<S>, key: &KeyNode) -> Res<Vec<u32>> {
    hive.value_offsets(key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksum_is_xor_of_header_words_and_zero_is_placeholder() {
        let mut head = vec![0_u8; BASE_BLOCK_SIZE as usize];
        head[0..4].copy_from_slice(b"regf");
        head[0x24..0x28].copy_from_slice(&0x20_u32.to_le_bytes());
        let computed = compute_checksum(&head);
        assert_eq!(computed, u32::from_le_bytes(*b"regf") ^ 0x20);
        head[0x1fc..0x200].copy_from_slice(&computed.to_le_bytes());
        // 校验和字段不在异或范围内：写入后计算值不变。
        assert_eq!(compute_checksum(&head), computed);
        let block = BaseBlock {
            sequence1: 1,
            sequence2: 1,
            last_write_raw: 0,
            major: 1,
            minor: 5,
            file_type: 0,
            file_format: 1,
            root_cell_offset: 0x20,
            hbins_size: 0x1000,
            clustering: 1,
            file_name: "SOFTWARE".to_owned(),
            checksum: computed,
            computed_checksum: computed,
        };
        assert!(block.checksum_ok());
        assert!(block.sequences_consistent());
        assert!(BaseBlock { checksum: 0, ..block.clone() }.checksum_ok());
        assert!(!BaseBlock { checksum: computed ^ 1, ..block }.checksum_ok());
    }

    #[test]
    fn short_and_foreign_files_are_rejected_before_parsing() {
        let error = Hive::open(SliceReader::new(&[0_u8; 64])).err().expect("短文件");
        assert_eq!(error.kind, ErrorKind::BadSignature);
        let mut bytes = vec![0_u8; 0x2000];
        bytes[0..4].copy_from_slice(b"REGF");
        let error = Hive::open(SliceReader::new(&bytes)).err().expect("魔数");
        assert_eq!(error.kind, ErrorKind::BadSignature);
        assert!(error.detail.contains("REGF"));
    }

    #[test]
    fn version_file_type_and_checksum_are_enforced() {
        let base = || {
            let mut bytes = vec![0_u8; 0x2000];
            bytes[0..4].copy_from_slice(b"regf");
            // hbin 头位于 base block 尾部 0x1000..0x1003。
            bytes[0x1000..0x1004].copy_from_slice(b"hbin");
            bytes[0x14..0x18].copy_from_slice(&1_u32.to_le_bytes());
            bytes[0x18..0x1c].copy_from_slice(&5_u32.to_le_bytes());
            bytes[0x28..0x2c].copy_from_slice(&0x1000_u32.to_le_bytes());
            bytes
        };
        let mut bytes = base();
        bytes[0x18..0x1c].copy_from_slice(&9_u32.to_le_bytes());
        assert_eq!(
            Hive::open(SliceReader::new(&bytes)).err().map(|e| e.kind),
            Some(ErrorKind::Corrupt)
        );
        let mut bytes = base();
        bytes[0x1c..0x20].copy_from_slice(&1_u32.to_le_bytes());
        assert_eq!(
            Hive::open(SliceReader::new(&bytes)).err().map(|e| e.kind),
            Some(ErrorKind::LogHeader)
        );
        let mut bytes = base();
        let checksum = compute_checksum(&bytes);
        bytes[0x1fc..0x200].copy_from_slice(&(checksum ^ 0xdead).to_le_bytes());
        assert_eq!(
            Hive::open(SliceReader::new(&bytes)).err().map(|e| e.kind),
            Some(ErrorKind::Corrupt)
        );
        // 占位 0 视为未写入，放行。
        assert!(Hive::open(SliceReader::new(&base())).is_ok());
    }

    #[test]
    fn truncated_hive_fails_with_declared_length() {
        let mut bytes = vec![0_u8; 0x2000];
        bytes[0..4].copy_from_slice(b"regf");
        bytes[0x1000..0x1004].copy_from_slice(b"hbin");
        bytes[0x14..0x18].copy_from_slice(&1_u32.to_le_bytes());
        bytes[0x18..0x1c].copy_from_slice(&5_u32.to_le_bytes());
        bytes[0x28..0x2c].copy_from_slice(&0x4000_u32.to_le_bytes());
        let error = Hive::open(SliceReader::new(&bytes)).err().expect("截断");
        assert_eq!(error.kind, ErrorKind::Corrupt);
        assert!(error.detail.contains("截断"));
    }

    #[test]
    fn names_compare_case_insensitively() {
        assert!(names_equal("Windows NT", "windows nt"));
        assert!(names_equal("CurrentVersion", "CURRENTVERSION"));
        assert!(!names_equal("CurrentVersion", "CurrentVersio"));
        assert!(names_equal("Über", "ÜBER"));
    }

    #[test]
    fn name_decoders_handle_both_encodings() {
        let raw: Vec<u8> = "中文值"
            .encode_utf16()
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert_eq!(decode_utf16le(&raw), "中文值");
        assert_eq!(decode_utf16le(&[0x41, 0x00, 0x42]), "A");
        assert_eq!(decode_compressed_name(b"ProgramFilesDir"), "ProgramFilesDir");
        assert_eq!(decode_compressed_name(&[0xE9]), "é");
        assert_eq!(hex_bytes(&[]), "(空)");
        assert_eq!(escaped_hex(&[0x72, 0x00]), "r\\x00");
    }

    #[test]
    fn multi_sz_drops_trailing_terminators() {
        let raw: Vec<u8> = ["a", "b", ""]
            .iter()
            .flat_map(|part| part.encode_utf16().chain(std::iter::once(0)).collect::<Vec<u16>>())
            .flat_map(|unit| unit.to_le_bytes())
            .collect();
        assert_eq!(decode_multi_sz(&raw), "a\nb");
    }
}