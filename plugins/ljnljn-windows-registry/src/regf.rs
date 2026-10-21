//! 注册表 hive(REGF)只读解析:文件头校验、hbin 结构校验、键(ck)/值(vk)与类名访问。
//!
//! 结构依据(通用公开格式,非案件取值):
//!   base block 0x000 magic "regf" | 0x004 seq1 | 0x008 seq2 | 0x00C last write
//!               0x014 major | 0x018 minor | 0x01C type | 0x020 format
//!               0x024 root cell rel offset | 0x028 hbins size | 0x030 file name
//!   hbin        0x000 magic "hbin" | 0x004 相对文件偏移 | 0x008 hbin 字节数(4KiB 对齐)
//!   cell        4 字节有符号长度:|len| 为单元总长,负数表示已分配
//!   nk(key)     0x000 id 0x6B6E | 0x002 flags | 0x014 子键数 | 0x01C 子键列表 rel
//!               0x024 值数 | 0x028 值列表 rel | 0x02C 类名 rel | 0x038 最大值名长
//!               0x03C 最大值数据长 | 0x044 键名长 | 0x048 类名长 | 0x04C 键名(UTF-16LE)
//!   vk(value)   0x000 id 0x6B76 | 0x002 值名长 | 0x004 数据长 | 0x008 数据 rel
//!               0x00C 数据类型 | 0x010 flags | 0x014 值名(UTF-16LE)
//!   lf/lh/li/ri 0x000 id | 0x002 条目数 | 0x004 .. 条目(rel)
//!   big data    0x000 id 0xDB | 0x002 段数 | 0x004 .. 段列表(rel),每段最多 16344 字节
//!
//! 所有偏移都做范围校验:越界返回 [`RegfStage::OffsetOutOfRange`],绝不 panic 或越界读。
//! 单元缓存放在 `RefCell` 里,所有访问方法取 `&self`(检材只读,不存在写回)。

use std::cell::RefCell;
use std::collections::HashMap;

pub const BASE_BLOCK_SIZE: usize = 0x1000;
const REGF_MAGIC: &[u8; 4] = b"regf";
const HBIN_MAGIC: &[u8; 4] = b"hbin";
const NK_ID: u16 = 0x6B6E; // "nk"
const VK_ID: u16 = 0x6B76; // "vk"
const DB_ID: u16 = u16::from_le_bytes(*b"db"); // big data cell signature
const LF_ID: u16 = u16::from_le_bytes(*b"lf");
const LH_ID: u16 = u16::from_le_bytes(*b"lh");
const LI_ID: u16 = u16::from_le_bytes(*b"li");
const RI_ID: u16 = u16::from_le_bytes(*b"ri");
const HBIN_ALIGN: u32 = 0x1000;
const BIG_SEGMENT: usize = 16344;

/// 最大嵌套键/列表深度,防御恶意构造的循环引用。
const MAX_DEPTH: usize = 512;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegfStage {
    /// base block 前 4 字节不是 "regf" 或长度不足
    Header,
    /// hbin 首部或长度自洽性校验失败
    Hbin,
    /// cell 结构(长度符号、匹配的结束单元)非法
    Cell,
    /// 请求的偏移超出 hive 或 hbin 范围
    OffsetOutOfRange,
    /// 键/值签名(id)不符
    Signature,
    /// 键(值/子键/类名)不存在
    Missing,
    /// 层级/列表嵌套超出限制
    DepthLimit,
    /// UTF-16LE 键名/值名解码失败
    Utf16,
}

impl RegfStage {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Header => "header",
            Self::Hbin => "hbin",
            Self::Cell => "cell",
            Self::OffsetOutOfRange => "offset_out_of_range",
            Self::Signature => "signature",
            Self::Missing => "missing",
            Self::DepthLimit => "depth_limit",
            Self::Utf16 => "utf16",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegfError {
    pub stage: RegfStage,
    pub message: String,
}

pub type RegfResult<T> = Result<T, RegfError>;

impl RegfError {
    pub fn new(stage: RegfStage, message: impl Into<String>) -> Self {
        Self {
            stage,
            message: message.into(),
        }
    }

    fn missing(path: &str) -> Self {
        Self::new(RegfStage::Missing, format!("键不存在: {path}"))
    }

    /// `消息stage=阶段` 的紧凑描述,便于写入 limitations
    pub fn describe(&self) -> String {
        format!("{}stage={}", self.message, self.stage.as_str())
    }
}

impl std::fmt::Display for RegfError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "[{}] {}", self.stage.as_str(), self.message)
    }
}

#[derive(Clone, Copy, Debug)]
struct CellInfo {
    /// 单元绝对偏移
    offset: u64,
    /// 数据区绝对偏移
    data: u64,
    /// 数据区有效长度
    len: u64,
    allocated: bool,
}

/// 已读入内存的 hive。只读访问,不做任何写回。
pub struct Hive {
    bytes: Vec<u8>,
    root_cell: u64,
    hbins_size: u32,
    cells: RefCell<HashMap<u64, CellInfo>>,
}

impl std::fmt::Debug for Hive {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Hive")
            .field("bytes", &self.bytes.len())
            .field("root_cell", &self.root_cell)
            .field("hbins_size", &self.hbins_size)
            .finish()
    }
}

#[derive(Clone, Debug)]
pub struct KeyNode {
    pub cell: u64,
    pub flags: u16,
    pub last_write_time: u64,
    pub subkey_count: u32,
    pub subkey_list: Option<u64>,
    pub value_count: u32,
    pub value_list: Option<u64>,
    pub class_name: Option<u64>,
    pub max_value_name_len: u32,
    pub max_value_data_len: u32,
    pub name_len: u16,
    pub class_len: u16,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct ValueNode {
    pub cell: u64,
    pub name: String,
    /// 值名在 vk 中的 UTF-16 字节数（内联数据起点 = 0x14 + name_len）。
    pub name_len: u16,
    pub data_len: u32,
    pub data: Option<u64>,
    pub data_type: u32,
    pub flags: u16,
}

impl ValueNode {
    /// 数据是否内联在 vk 结构内(高位标志)
    pub fn is_inline(&self) -> bool {
        self.data_len & 0x8000_0000 != 0
    }

    pub fn effective_len(&self) -> u32 {
        self.data_len & 0x7FFF_FFFF
    }
}

impl Hive {
    /// 校验 REGF base block 与全部 hbin 首部,成功后才允许后续解析。
    pub fn open(bytes: Vec<u8>) -> RegfResult<Self> {
        if bytes.len() < BASE_BLOCK_SIZE {
            return Err(RegfError::new(
                RegfStage::Header,
                format!(
                    "文件长度 {} 小于 REGF base block 0x{BASE_BLOCK_SIZE:X} 字节",
                    bytes.len()
                ),
            ));
        }
        if &bytes[0..4] != REGF_MAGIC {
            return Err(RegfError::new(
                RegfStage::Header,
                format!("base block magic 期望 regf,实际 {:02X?}", &bytes[0..4]),
            ));
        }
        let hbins_size = read_u32(&bytes, 0x28)
            .ok_or_else(|| RegfError::new(RegfStage::Header, "base block 截断"))?;
        let root_cell = u64::from(
            read_u32(&bytes, 0x24)
                .ok_or_else(|| RegfError::new(RegfStage::Header, "base block 截断"))?,
        );
        let major = read_u32(&bytes, 0x14).unwrap_or(0);
        let minor = read_u32(&bytes, 0x18).unwrap_or(0);
        if major != 1 || minor > 6 {
            return Err(RegfError::new(
                RegfStage::Header,
                format!("不支持的 regf 版本 {major}.{minor}（仅支持 1.0–1.6）"),
            ));
        }
        let file_type = read_u32(&bytes, 0x1C).unwrap_or(1);
        if file_type != 0 {
            return Err(RegfError::new(
                RegfStage::Header,
                format!("base block 文件类型 {file_type} 不是主 hive（0）"),
            ));
        }
        if hbins_size == 0 || hbins_size % HBIN_ALIGN != 0 {
            return Err(RegfError::new(
                RegfStage::Hbin,
                format!("hbin 区域长度 {hbins_size} 未按 0x{HBIN_ALIGN:X} 对齐或为 0"),
            ));
        }
        let hbins_end = BASE_BLOCK_SIZE as u64 + u64::from(hbins_size);
        if hbins_end > bytes.len() as u64 {
            return Err(RegfError::new(
                RegfStage::Hbin,
                format!(
                    "hbin 区域止于 0x{hbins_end:X},超过文件长度 0x{:X}",
                    bytes.len()
                ),
            ));
        }
        let hive = Self {
            bytes,
            root_cell,
            hbins_size,
            cells: RefCell::new(HashMap::new()),
        };
        hive.validate_hbins()?;
        // 根键必须是合法 nk
        let root = hive.key(root_cell)?;
        if root.cell != root_cell {
            return Err(RegfError::new(RegfStage::Signature, "根键单元异常"));
        }
        Ok(hive)
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn raw(&self) -> &[u8] {
        &self.bytes
    }

    pub fn root_cell(&self) -> u64 {
        self.root_cell
    }

    pub fn hbins_size(&self) -> u32 {
        self.hbins_size
    }

    fn hbins_end(&self) -> u64 {
        BASE_BLOCK_SIZE as u64 + u64::from(self.hbins_size)
    }

    fn validate_hbins(&self) -> RegfResult<()> {
        let hbins_end = self.hbins_end();
        let mut offset = BASE_BLOCK_SIZE as u64;
        while offset < hbins_end {
            let header = self
                .bytes
                .get(offset as usize..offset as usize + 0x20)
                .ok_or_else(|| {
                    RegfError::new(RegfStage::Hbin, format!("hbin 首部 @0x{offset:X} 越界"))
                })?;
            if &header[0..4] != HBIN_MAGIC {
                return Err(RegfError::new(
                    RegfStage::Hbin,
                    format!(
                        "hbin @0x{offset:X} magic 期望 hbin,实际 {:02X?}",
                        &header[0..4]
                    ),
                ));
            }
            let declared = read_u32(&self.bytes, offset as usize + 0x04).unwrap_or(0);
            let relative = offset - BASE_BLOCK_SIZE as u64;
            if u64::from(declared) != relative {
                return Err(RegfError::new(
                    RegfStage::Hbin,
                    format!(
                        "hbin @0x{offset:X} 偏移字段 {declared} 与相对偏移 0x{relative:X} 不符"
                    ),
                ));
            }
            let size = read_u32(&self.bytes, offset as usize + 0x08).unwrap_or(0);
            if size == 0 || size % HBIN_ALIGN != 0 {
                return Err(RegfError::new(
                    RegfStage::Hbin,
                    format!("hbin @0x{offset:X} 长度 {size} 非法(须 0x{HBIN_ALIGN:X} 对齐)"),
                ));
            }
            let end = offset + u64::from(size);
            if end > hbins_end {
                return Err(RegfError::new(
                    RegfStage::Hbin,
                    format!("hbin @0x{offset:X} 止于 0x{end:X},越过 hbin 区域"),
                ));
            }
            self.walk_cells(offset + 0x20, end)?;
            offset = end;
        }
        Ok(())
    }

    /// 线性校验 hbin 内单元链:每对 cell 的长度符号必须一致。
    /// `start..end` 是绝对文件偏移;缓存键用相对偏移(hbin 区域起点为 0)。
    fn walk_cells(&self, start: u64, end: u64) -> RegfResult<()> {
        let mut cursor = start;
        while cursor < end {
            let raw = self.cell_raw_len(cursor)?;
            let length = raw.unsigned_abs() as u64;
            if length < 8 || length % 8 != 0 {
                return Err(RegfError::new(
                    RegfStage::Cell,
                    format!("cell @0x{cursor:X} 长度 {raw} 非法(须为 8 的倍数且 ≥8)"),
                ));
            }
            if cursor + length > end {
                return Err(RegfError::new(
                    RegfStage::Cell,
                    format!(
                        "cell @0x{cursor:X} 止于 0x{:X},越过 hbin 末 0x{end:X}",
                        cursor + length
                    ),
                ));
            }
            // 真实 hive 只在 cell 起点写长度；末尾 4 字节属于载荷/空闲区，
            // 不能当作第二个长度字段校验（v1 的严格实现会误拒合法 hive）。
            self.cells.borrow_mut().insert(
                cursor - BASE_BLOCK_SIZE as u64,
                CellInfo {
                    offset: cursor - BASE_BLOCK_SIZE as u64,
                    data: cursor + 4,
                    len: length - 4,
                    allocated: raw < 0,
                },
            );
            cursor += length;
        }
        Ok(())
    }

    fn cell_raw_len(&self, absolute: u64) -> RegfResult<i32> {
        let start = usize::try_from(absolute)
            .ok()
            .filter(|start| *start + 4 <= self.bytes.len())
            .ok_or_else(|| {
                RegfError::new(
                    RegfStage::OffsetOutOfRange,
                    format!("cell 长度字段 @绝对 0x{absolute:X} 越界"),
                )
            })?;
        Ok(i32::from_le_bytes([
            self.bytes[start],
            self.bytes[start + 1],
            self.bytes[start + 2],
            self.bytes[start + 3],
        ]))
    }

    /// 取单元信息。`relative` 为 hive 内存储的相对偏移(以 hbin 区域起点为基准)。
    fn cell(&self, relative: u64) -> RegfResult<CellInfo> {
        if let Some(info) = self.cells.borrow().get(&relative) {
            return Ok(*info);
        }
        let hbins_end = self.hbins_end();
        let absolute = BASE_BLOCK_SIZE as u64 + relative;
        if relative >= u64::from(self.hbins_size) || absolute + 4 > hbins_end {
            return Err(RegfError::new(
                RegfStage::OffsetOutOfRange,
                format!(
                    "cell 相对偏移 0x{relative:X}(绝对 0x{absolute:X})不在 hbin 区域 [0x{BASE_BLOCK_SIZE:X}, 0x{hbins_end:X})"
                ),
            ));
        }
        let raw = self.cell_raw_len(absolute)?;
        let length = raw.unsigned_abs() as u64;
        if length < 8 || length % 8 != 0 || absolute + length > hbins_end {
            return Err(RegfError::new(
                RegfStage::Cell,
                format!("cell @相对 0x{relative:X} 长度 {raw} 非法"),
            ));
        }
        let info = CellInfo {
            offset: relative,
            data: absolute + 4,
            len: length - 4,
            allocated: raw < 0,
        };
        self.cells.borrow_mut().insert(relative, info);
        Ok(info)
    }

    fn cell_data(&self, offset: u64) -> RegfResult<(CellInfo, &[u8])> {
        let info = self.cell(offset)?;
        let start = usize::try_from(info.data).map_err(|_| {
            RegfError::new(RegfStage::OffsetOutOfRange, "cell 数据区偏移超出地址空间")
        })?;
        let end = usize::try_from(info.len)
            .ok()
            .and_then(|len| start.checked_add(len))
            .filter(|end| *end <= self.bytes.len())
            .ok_or_else(|| {
                RegfError::new(
                    RegfStage::OffsetOutOfRange,
                    format!("cell @0x{offset:X} 数据区超出文件末尾"),
                )
            })?;
        Ok((info, &self.bytes[start..end]))
    }

    /// 键名(UTF-16LE)
    pub fn key_name_at(&self, cell: u64) -> RegfResult<String> {
        Ok(self.key(cell)?.name)
    }

    /// 键结构
    pub fn key(&self, cell: u64) -> RegfResult<KeyNode> {
        let (info, data) = self.cell_data(cell)?;
        if data.len() < 0x4C {
            return Err(RegfError::new(
                RegfStage::Cell,
                format!("nk @0x{cell:X} 长度 {} 不足以容纳键头", data.len()),
            ));
        }
        let id = u16::from_le_bytes([data[0], data[1]]);
        if id != NK_ID {
            return Err(RegfError::new(
                RegfStage::Signature,
                format!("cell @0x{cell:X} 签名期望 nk(0x{NK_ID:04X}),实际 0x{id:04X}"),
            ));
        }
        let name_len = u16::from_le_bytes([data[0x48], data[0x49]]);
        let class_len = u16::from_le_bytes([data[0x4A], data[0x4B]]);
        let name_end = 0x4C_usize
            .checked_add(usize::from(name_len))
            .filter(|end| *end <= data.len())
            .ok_or_else(|| {
                RegfError::new(
                    RegfStage::Cell,
                    format!(
                        "nk @0x{cell:X} 名称 {name_len} 字节越过单元长度 {}",
                        data.len()
                    ),
                )
            })?;
        let name = utf16_name(&data[0x4C..name_end], RegfStage::Utf16)?;
        Ok(KeyNode {
            cell: info.offset,
            flags: u16::from_le_bytes([data[0x02], data[0x03]]),
            last_write_time: read_u64(data, 0x04).unwrap_or(0),
            subkey_count: read_u32(data, 0x14).unwrap_or(0),
            subkey_list: rel_or_none(data, 0x1C),
            value_count: read_u32(data, 0x24).unwrap_or(0),
            value_list: rel_or_none(data, 0x28),
            class_name: rel_or_none(data, 0x2C),
            max_value_name_len: read_u32(data, 0x38).unwrap_or(0),
            max_value_data_len: read_u32(data, 0x3C).unwrap_or(0),
            name_len,
            class_len,
            name,
        })
    }

    /// 键的类名(UTF-16LE,按 class_len 截断)
    pub fn key_class(&self, cell: u64) -> RegfResult<String> {
        let key = self.key(cell)?;
        let Some(class_cell) = key.class_name else {
            return Ok(String::new());
        };
        let (_, data) = self.cell_data(class_cell)?;
        let len = usize::from(key.class_len).min(data.len());
        if len == 0 {
            return Ok(String::new());
        }
        let raw = &data[..len];
        // LSA 的 JD/Skew1/GBG/Data 类名是 8 个 ASCII 十六进制字符；
        // 其它类名按 UTF-16LE 解码。不能一律按 UTF-16LE，否则
        // "01020304" 会变成 "㌸㝁㌳㜷"，bootkey 派生随即失败。
        if raw.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            return Ok(String::from_utf8_lossy(raw).trim_end_matches('\0').to_string());
        }
        Ok(utf16_name(raw, RegfStage::Utf16)
            .unwrap_or_default()
            .trim_end_matches('\0')
            .to_string())
    }

    /// 逐级下行定位键,失败时给出具体路径与阶段。
    pub fn open_key(&self, path: &[&str]) -> RegfResult<u64> {
        let mut current = self.root_cell;
        let mut walked: Vec<&str> = Vec::new();
        for component in path {
            if component.is_empty() {
                continue;
            }
            walked.push(component);
            let mut found = None;
            for subkey in self.subkey_cells(current)? {
                if self.key_name_at(subkey)? == *component {
                    found = Some(subkey);
                    break;
                }
            }
            current = found.ok_or_else(|| RegfError::missing(&walked.join("\\")))?;
        }
        Ok(current)
    }

    /// 直接子键单元列表(解析 lf/lh/li/ri)
    pub fn subkey_cells(&self, cell: u64) -> RegfResult<Vec<u64>> {
        let key = self.key(cell)?;
        let Some(list) = key.subkey_list else {
            return Ok(Vec::new());
        };
        if key.subkey_count == 0 {
            return Ok(Vec::new());
        }
        self.subkey_list(list, key.subkey_count as usize, 0)
    }

    fn subkey_list(&self, list: u64, expected: usize, depth: usize) -> RegfResult<Vec<u64>> {
        if depth > MAX_DEPTH {
            return Err(RegfError::new(
                RegfStage::DepthLimit,
                format!("子键列表嵌套超过 {MAX_DEPTH} 层"),
            ));
        }
        let (_, data) = self.cell_data(list)?;
        if data.len() < 4 {
            return Err(RegfError::new(
                RegfStage::Cell,
                format!("子键列表 @0x{list:X} 过短"),
            ));
        }
        let id = u16::from_le_bytes([data[0], data[1]]);
        let count = u16::from_le_bytes([data[2], data[3]]) as usize;
        let mut offsets = Vec::new();
        match id {
            LF_ID | LH_ID | LI_ID => {
                if 4 + count * 4 > data.len() {
                    return Err(RegfError::new(
                        RegfStage::Cell,
                        format!(
                            "子键列表 @0x{list:X} 声明 {count} 项,超出单元长度 {}",
                            data.len()
                        ),
                    ));
                }
                for index in 0..count {
                    offsets.push(read_u32(data, 4 + index * 4).unwrap_or(0) as u64);
                }
            }
            RI_ID => {
                if 4 + count * 4 > data.len() {
                    return Err(RegfError::new(
                        RegfStage::Cell,
                        format!("索引根 @0x{list:X} 条目越界"),
                    ));
                }
                for index in 0..count {
                    let child = read_u32(data, 4 + index * 4).unwrap_or(0) as u64;
                    offsets.extend(self.subkey_list(child, expected, depth + 1)?);
                }
            }
            other => {
                return Err(RegfError::new(
                    RegfStage::Signature,
                    format!("子键列表 @0x{list:X} 签名 0x{other:04X} 未知"),
                ))
            }
        }
        if result_count(&offsets) != expected && id != RI_ID {            return Err(RegfError::new(
                RegfStage::Cell,
                format!(
                    "子键列表 @0x{list:X} 实际 {} 项与 nk 声明 {expected} 项不一致",
                    offsets.len()
                ),
            ));
        }
        Ok(offsets)
    }

    /// 键下全部值(按 vk 单元顺序)
    pub fn values(&self, cell: u64) -> RegfResult<Vec<ValueNode>> {
        let key = self.key(cell)?;
        let Some(list) = key.value_list else {
            return Ok(Vec::new());
        };
        if key.value_count == 0 {
            return Ok(Vec::new());
        }
        let (_, data) = self.cell_data(list)?;
        if key.value_count as usize * 4 > data.len() {
            return Err(RegfError::new(
                RegfStage::Cell,
                format!(
                    "值列表 @0x{list:X} 声明 {} 项,超出单元长度 {}",
                    key.value_count,
                    data.len()
                ),
            ));
        }
        let mut offsets = Vec::with_capacity(key.value_count as usize);
        for index in 0..key.value_count as usize {
            offsets.push(read_u32(data, index * 4).unwrap_or(0) as u64);
        }
        let mut values = Vec::with_capacity(offsets.len());
        for offset in offsets {
            values.push(self.value(offset)?);
        }
        Ok(values)
    }

    fn value(&self, cell: u64) -> RegfResult<ValueNode> {
        let (info, data) = self.cell_data(cell)?;
        if data.len() < 0x14 {
            return Err(RegfError::new(
                RegfStage::Cell,
                format!("vk @0x{cell:X} 长度 {} 不足以容纳值头", data.len()),
            ));
        }
        let id = u16::from_le_bytes([data[0], data[1]]);
        if id != VK_ID {
            return Err(RegfError::new(
                RegfStage::Signature,
                format!("值单元 @0x{cell:X} 签名期望 vk,实际 0x{id:04X}"),
            ));
        }
        let name_len = u16::from_le_bytes([data[2], data[3]]);
        let name_end = 0x14_usize
            .checked_add(usize::from(name_len))
            .filter(|end| *end <= data.len())
            .ok_or_else(|| {
                RegfError::new(
                    RegfStage::Cell,
                    format!(
                        "vk @0x{cell:X} 名称 {name_len} 字节越过单元长度 {}",
                        data.len()
                    ),
                )
            })?;
        let name = utf16_name(&data[0x14..name_end], RegfStage::Utf16)?;
        let data_len = read_u32(data, 4).unwrap_or(0);
        let data_rel = read_u32(data, 8).unwrap_or(0xFFFF_FFFF);
        let inline = data_len & 0x8000_0000 != 0;
        let data_offset = if inline || data_len == 0 || data_rel == 0xFFFF_FFFF {
            None
        } else {
            Some(u64::from(data_rel))
        };
        Ok(ValueNode {
            cell: info.offset,
            name,
            name_len,
            data_len,
            data: data_offset,
            data_type: read_u32(data, 0xC).unwrap_or(0),
            flags: u16::from_le_bytes([data[0x10], data[0x11]]),
        })
    }

    /// 值的原始数据(内联、big data 分段均按规范拼回)
    pub fn value_data(&self, value: &ValueNode) -> RegfResult<Vec<u8>> {
        let len = value.effective_len() as usize;
        if value.is_inline() {
            let (_, data) = self.cell_data(value.cell)?;
            let start = 0x14 + usize::from(value.name_len);
            let mut out = data.get(start..).map(|slice| slice.to_vec()).unwrap_or_default();
            out.truncate(len.min(4));
            return Ok(out);
        }
        let Some(offset) = value.data else {
            return Ok(Vec::new());
        };
        let (_, data) = self.cell_data(offset)?;
        if data.len() >= 2 && u16::from_le_bytes([data[0], data[1]]) == DB_ID {
            let segments = u16::from_le_bytes([data[2], data[3]]) as usize;
            if 4 + segments * 4 > data.len() {
                return Err(RegfError::new(
                    RegfStage::Cell,
                    format!("big data @0x{offset:X} 段列表越界"),
                ));
            }
            let mut segment_offsets = Vec::with_capacity(segments);
            for index in 0..segments {
                segment_offsets.push(read_u32(data, 4 + index * 4).unwrap_or(0) as u64);
            }
            let mut out = Vec::with_capacity(len);
            for segment in segment_offsets {
                let (_, segment_data) = self.cell_data(segment)?;
                let take = segment_data.len().min(BIG_SEGMENT);
                let take = take.min(len.saturating_sub(out.len()));
                out.extend_from_slice(&segment_data[..take]);
                if out.len() >= len {
                    break;
                }
            }
            if out.len() < len {
                return Err(RegfError::new(
                    RegfStage::Cell,
                    format!(
                        "big data @0x{offset:X} 拼接后仅 {} 字节,期望 {len}",
                        out.len()
                    ),
                ));
            }
            return Ok(out);
        }
        if len > data.len() {
            return Err(RegfError::new(
                RegfStage::Cell,
                format!(
                    "值数据 @0x{offset:X} 声明 {len} 字节,单元仅 {} 字节",
                    data.len()
                ),
            ));
        }
        Ok(data[..len].to_vec())
    }

    /// 只取值数据的前 `prefix` 字节
    pub fn value_data_prefix(&self, value: &ValueNode, prefix: usize) -> RegfResult<Vec<u8>> {
        let all = self.value_data(value)?;
        Ok(all[..all.len().min(prefix)].to_vec())
    }
}

fn result_count(offsets: &[u64]) -> usize {
    offsets.len()
}

fn rel_or_none(data: &[u8], offset: usize) -> Option<u64> {
    let raw = read_u32(data, offset)?;
    if raw == 0xFFFF_FFFF || raw == 0 {
        None
    } else {
        Some(u64::from(raw))
    }
}

fn utf16_name(bytes: &[u8], stage: RegfStage) -> RegfResult<String> {
    if bytes.len() % 2 != 0 {
        return Err(RegfError::new(stage, "UTF-16LE 名称字节数为奇数"));
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    String::from_utf16(&units)
        .map_err(|error| RegfError::new(stage, format!("UTF-16LE 名称解码失败: {error}")))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|slice| u32::from_le_bytes(slice.try_into().unwrap_or([0; 4])))
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    bytes
        .get(offset..offset + 8)
        .map(|slice| u64::from_le_bytes(slice.try_into().unwrap_or([0; 8])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhive::{build_hive, KeySpec};

    #[test]
    fn empty_hive_parses_and_root_is_reachable() {
        let bytes = build_hive(&KeySpec::new("SYSTEM"));
        let hive = Hive::open(bytes).expect("parses");
        assert!(hive.len() > BASE_BLOCK_SIZE);
        assert_eq!(hive.key_name_at(hive.root_cell()).expect("root"), "SYSTEM");
    }

    #[test]
    fn missing_key_reports_missing_stage_with_path() {
        let bytes = build_hive(&KeySpec::new("SYSTEM"));
        let hive = Hive::open(bytes).expect("parses");
        let error = hive.open_key(&["CurrentControlSet"]).expect_err("missing");
        assert_eq!(error.stage, RegfStage::Missing);
        assert!(error.message.contains("CurrentControlSet"));
    }

    #[test]
    fn value_data_round_trips() {
        let spec = KeySpec::new("SYSTEM").value("F", 3, vec![1, 2, 3, 4, 5, 6]);
        let hive = Hive::open(build_hive(&spec)).expect("parses");
        let values = hive.values(hive.root_cell()).expect("values");
        assert_eq!(values.len(), 1);
        assert_eq!(values[0].name, "F");
        assert_eq!(
            hive.value_data(&values[0]).expect("data"),
            vec![1u8, 2, 3, 4, 5, 6]
        );
    }

    #[test]
    fn inline_value_data_is_read_from_value_header() {
        let spec = KeySpec::new("SYSTEM").value("D", 4, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let hive = Hive::open(build_hive(&spec)).expect("parses");
        let values = hive.values(hive.root_cell()).expect("values");
        assert!(values[0].is_inline());
        assert_eq!(
            hive.value_data(&values[0]).expect("data"),
            vec![0xAAu8, 0xBB, 0xCC, 0xDD]
        );
    }

    #[test]
    fn inline_value_with_non_ascii_name_uses_utf16_name_length() {
        let spec = KeySpec::new("SYSTEM").value("密码", 4, vec![0xAA, 0xBB, 0xCC, 0xDD]);
        let hive = Hive::open(build_hive(&spec)).expect("parses");
        let values = hive.values(hive.root_cell()).expect("values");
        assert!(values[0].is_inline());
        assert_eq!(
            hive.value_data(&values[0]).expect("data"),
            vec![0xAAu8, 0xBB, 0xCC, 0xDD]
        );
    }

    #[test]
    fn class_name_is_read_for_lsa_subkeys() {
        let spec = KeySpec::new("SYSTEM").child(
            KeySpec::new("Control").child(KeySpec::new("Lsa").child(
                KeySpec::new("JD").class(b"01020304".to_vec()),
            )),
        );
        let hive = Hive::open(build_hive(&spec)).expect("parses");
        let jd = hive
            .open_key(&["Control", "Lsa", "JD"])
            .expect("JD exists");
        assert_eq!(hive.key_class(jd).expect("class"), "01020304");
    }

    #[test]
    fn bad_signature_is_reported() {
        let mut bytes = build_hive(&KeySpec::new("SYSTEM"));
        // 把根键签名破坏成非 nk
        let root = 0x1000 + u32::from_le_bytes(bytes[0x24..0x28].try_into().unwrap()) as usize;
        bytes[root..root + 2].copy_from_slice(&0x1234u16.to_le_bytes());
        let error = Hive::open(bytes).expect_err("bad nk");
        assert!(matches!(error.stage, RegfStage::Signature | RegfStage::Cell));
    }
}
