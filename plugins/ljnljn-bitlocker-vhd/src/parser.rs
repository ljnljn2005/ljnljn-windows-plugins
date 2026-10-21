//! 纯字节解析：VHD/VHDX 格式识别、BitLocker `-FVE-FS-` 扫描与 FVE 元数据只读解析。
//!
//! 本模块不接触宿主、文件句柄或时钟，所有读取都通过 [`ImageReader`] 进行，
//! 因此可以用合成字节完整做单元测试。生产路径由 `lib.rs` 把 SDK 的只读
//! `File` 包装成 `ImageReader`。
//!
//! 解析边界：
//!
//! 1. **VHD**：文件最后 512 字节的 footer 以 `conectix` 开头；读取磁盘类型、
//!    当前大小与原始 16 字节 unique id（按原始字节输出，不推断 UUID 端序）。
//! 2. **VHDX**：文件头前 8 字节为 `vhdxfile`；读取 512 字节 UTF-16LE creator。
//! 3. **BitLocker 签名**：在文件前 [`MAX_SCAN_BYTES`] 字节内按 4 MiB 分块扫描
//!    `2D 46 56 45 2D 46 53 2D`，块间保留 7 字节重叠，输出文件绝对偏移。
//! 4. **FVE 元数据**：仅对“签名前 3 字节为 `EB ?? 90`”的引导卷头候选解析；
//!    尝试 Windows 7+ 卷头的 176/184/192 字节处三个元数据块偏移。
//!    元数据块头、元数据头与条目都做边界和长度校验，越界即停止并记录原因。
//! 5. **恢复密钥 GUID**：只取 VMK 条目（entry type 0x0002、value type 0x0008）
//!    中 protection type = 0x0800（恢复密码）的 16 字节标识符。找不到就明确
//!    写入 limitations，不从文件名、txt 或其它字段猜测。
//!
//! 不做：解密、挂载、执行镜像内容、分区表/文件系统解析、VHD 动态块展开、
//! 差异盘链、VHD/VHDX 校验和验证、Vista 卷头布局、BitLocker To Go FAT
//! （`MSWIN4.1`）布局、外部恢复密钥文件匹配。

use std::fmt::Write as _;

/// BitLocker 引导/元数据块签名。
pub const FVE_SIGNATURE: &[u8] = b"-FVE-FS-";

/// VHD footer cookie。
pub const VHD_COOKIE: &[u8] = b"conectix";

/// VHDX 文件标识签名。
pub const VHDX_MAGIC: &[u8] = b"vhdxfile";

/// VHD footer 固定长度。
pub const VHD_FOOTER_SIZE: u64 = 512;

/// VHDX creator 字段长度。
pub const VHDX_CREATOR_SIZE: usize = 512;

/// 单次从 `ImageReader` 读取的扫描块大小（与 SDK `MAX_HOST_READ` 一致）。
pub const SCAN_CHUNK_BYTES: usize = 4 * 1024 * 1024;

/// 扫描上限；超过部分不读取，并在结果 limitations 中标注。
pub const MAX_SCAN_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// 单次分析最多记录的 `-FVE-FS-` 命中数。
pub const MAX_SIGNATURE_HITS: usize = 64;

/// 单个 FVE 元数据块大小上限，避免畸形长度导致过量读取。
pub const MAX_METADATA_BYTES: u32 = 1024 * 1024;

/// 每个元数据块最多解析的 VMK 条目数。
pub const MAX_VMK_ENTRIES: usize = 64;

/// FVE 元数据块头长度。
pub const METADATA_BLOCK_HEADER_SIZE: u64 = 64;

/// FVE 元数据头（v1）长度。
pub const METADATA_HEADER_SIZE: u32 = 48;

/// Windows 7+ NTFS 卷头中三个 FVE 元数据块偏移字段。
pub const METADATA_OFFSET_FIELDS: [usize; 3] = [176, 184, 192];

/// VMK 条目类型。
pub const ENTRY_TYPE_VMK: u16 = 0x0002;

/// VMK value type。
pub const VALUE_TYPE_VMK: u16 = 0x0008;

/// 恢复密码保护类型。
pub const PROTECTION_TYPE_RECOVERY_PASSWORD: u16 = 0x0800;

/// 只读随机访问抽象；生产实现包装 SDK `File`，测试实现包装内存切片。
pub trait ImageReader {
    fn size(&self) -> u64;
    fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, String>;
}

/// 镜像格式。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Format {
    Vhd,
    Vhdx,
    Unknown,
}

impl Format {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Vhd => "vhd",
            Self::Vhdx => "vhdx",
            Self::Unknown => "unknown",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Vhd => "VHD（文件尾 conectix）",
            Self::Vhdx => "VHDX（文件头 vhdxfile）",
            Self::Unknown => "未知（未识别为 VHD/VHDX）",
        }
    }
}

/// VHD footer 中与识别相关的字段。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VhdFooterInfo {
    pub footer_offset: u64,
    pub disk_type: u32,
    pub current_size: u64,
    /// footer 中 16 字节 unique id 的原始十六进制，未推断 UUID 端序。
    pub unique_id_hex: String,
}

impl VhdFooterInfo {
    pub fn disk_type_label(&self) -> &'static str {
        match self.disk_type {
            2 => "固定磁盘",
            3 => "动态磁盘",
            4 => "差异磁盘",
            _ => "未知磁盘类型",
        }
    }
}

/// VHDX 文件标识中的 creator 字段。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VhdxHeaderInfo {
    pub creator: String,
}

/// 格式识别结果。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FormatInfo {
    pub format: Format,
    pub signature_offset: Option<u64>,
    pub vhd: Option<VhdFooterInfo>,
    pub vhdx: Option<VhdxHeaderInfo>,
}

impl FormatInfo {
    pub fn signature(&self) -> Option<&'static str> {
        match self.format {
            Format::Vhd => Some("conectix"),
            Format::Vhdx => Some("vhdxfile"),
            Format::Unknown => None,
        }
    }
}

/// 识别 VHD/VHDX。`header` 为文件开头（至少 520 字节可解析 creator），
/// `footer` 为文件最后 512 字节（文件不足 512 字节时为 `None`）。
pub fn detect_format(file_size: u64, header: &[u8], footer: Option<&[u8]>) -> FormatInfo {
    if header.len() >= VHDX_MAGIC.len() && &header[..VHDX_MAGIC.len()] == VHDX_MAGIC {
        let creator_end = header
            .len()
            .min(VHDX_MAGIC.len().saturating_add(VHDX_CREATOR_SIZE));
        let creator = decode_utf16le(&header[VHDX_MAGIC.len()..creator_end]);
        return FormatInfo {
            format: Format::Vhdx,
            signature_offset: Some(0),
            vhd: None,
            vhdx: Some(VhdxHeaderInfo { creator }),
        };
    }

    if let Some(footer) = footer {
        if footer.len() >= VHD_FOOTER_SIZE as usize && &footer[..VHD_COOKIE.len()] == VHD_COOKIE {
            return FormatInfo {
                format: Format::Vhd,
                signature_offset: Some(file_size.saturating_sub(VHD_FOOTER_SIZE)),
                vhd: Some(VhdFooterInfo {
                    footer_offset: file_size.saturating_sub(VHD_FOOTER_SIZE),
                    disk_type: be_u32(footer, 60),
                    current_size: be_u64(footer, 48),
                    unique_id_hex: hex_upper(&footer[68..84]),
                }),
                vhdx: None,
            };
        }
    }

    FormatInfo {
        format: Format::Unknown,
        signature_offset: None,
        vhd: None,
        vhdx: None,
    }
}

/// BitLocker 签名扫描结果。
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ScanOutcome {
    pub offsets: Vec<u64>,
    pub bytes_scanned: u64,
    pub scan_limit: u64,
    /// 文件大于扫描上限，只扫描了前 `scan_limit` 字节。
    pub truncated: bool,
    /// 命中达到上限，扫描提前结束。
    pub hit_limit_reached: bool,
}

/// 按 [`MAX_SCAN_BYTES`] 上限扫描 BitLocker 签名。
pub fn scan_for_signatures<R: ImageReader + ?Sized>(
    reader: &R,
    chunk_size: usize,
    max_hits: usize,
    check_cancelled: impl FnMut() -> Result<(), String>,
) -> Result<ScanOutcome, String> {
    let scan_limit = reader.size().min(MAX_SCAN_BYTES);
    scan_for_signatures_with_limit(reader, scan_limit, chunk_size, max_hits, check_cancelled)
}

/// 在调用方给定上限内扫描 BitLocker 签名（测试可注入小上限）。
pub fn scan_for_signatures_with_limit<R: ImageReader + ?Sized>(
    reader: &R,
    scan_limit: u64,
    chunk_size: usize,
    max_hits: usize,
    mut check_cancelled: impl FnMut() -> Result<(), String>,
) -> Result<ScanOutcome, String> {
    let file_size = reader.size();
    let scan_limit = scan_limit.min(file_size);
    let chunk_size = chunk_size.max(FVE_SIGNATURE.len()).max(1);
    let max_hits = max_hits.max(1);

    let mut offsets = Vec::new();
    let mut position = 0_u64;
    let mut carry: Vec<u8> = Vec::new();
    let mut hit_limit_reached = false;

    while position < scan_limit {
        check_cancelled()?;
        let want = ((scan_limit - position).min(chunk_size as u64)) as usize;
        let data = reader.read_at(position, want)?;
        if data.is_empty() {
            return Err(format!(
                "偏移 {position} 处应有 {want} 字节，但读取结果为空；拒绝在缺失数据上继续扫描"
            ));
        }
        if data.len() < want {
            return Err(format!(
                "偏移 {position} 处请求 {want} 字节，只读到 {} 字节；拒绝在缺失数据上继续扫描",
                data.len()
            ));
        }

        let base = position - carry.len() as u64;
        let mut window = Vec::with_capacity(carry.len() + data.len());
        window.extend_from_slice(&carry);
        window.extend_from_slice(&data);
        hit_limit_reached = find_signatures(&window, base, &mut offsets, max_hits);

        position += data.len() as u64;
        if hit_limit_reached {
            break;
        }
        let keep = window.len().min(FVE_SIGNATURE.len() - 1);
        carry.clear();
        carry.extend_from_slice(&window[window.len() - keep..]);
    }

    Ok(ScanOutcome {
        offsets,
        bytes_scanned: position,
        scan_limit,
        truncated: scan_limit < file_size,
        hit_limit_reached,
    })
}

/// 在 `window` 中查找签名；返回是否达到命中上限。
fn find_signatures(window: &[u8], base: u64, offsets: &mut Vec<u64>, max_hits: usize) -> bool {
    let mut start = 0;
    while start + FVE_SIGNATURE.len() <= window.len() {
        let Some(relative) = window[start..]
            .iter()
            .position(|byte| *byte == FVE_SIGNATURE[0])
        else {
            return false;
        };
        let index = start + relative;
        if index + FVE_SIGNATURE.len() > window.len() {
            return false;
        }
        if &window[index..index + FVE_SIGNATURE.len()] == FVE_SIGNATURE {
            offsets.push(base + index as u64);
            if offsets.len() >= max_hits {
                return true;
            }
            start = index + FVE_SIGNATURE.len();
        } else {
            start = index + 1;
        }
    }
    false
}

/// 单个命中的解析状态。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseStatus {
    Parsed,
    NotBootHeader,
    NoMetadata,
    InvalidMetadata,
}

impl ParseStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Parsed => "parsed",
            Self::NotBootHeader => "not_boot_header",
            Self::NoMetadata => "no_metadata",
            Self::InvalidMetadata => "invalid_metadata",
        }
    }
}

/// 本次解析依据：启动卷头、独立元数据块，或未解析。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseBasis {
    BootHeader,
    MetadataBlock,
    None,
}

impl ParseBasis {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BootHeader => "boot_header",
            Self::MetadataBlock => "metadata_block",
            Self::None => "none",
        }
    }
}

/// 一个 VMK 条目。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VmkEntry {
    pub guid: String,
    pub protection_type: u16,
    pub is_recovery_key: bool,
}

/// 一个已解析的 FVE 元数据块。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FveMetadata {
    pub block_offset: u64,
    pub block_version: u16,
    pub metadata_offset: u64,
    pub metadata_size: u32,
    pub volume_id: Option<String>,
    pub encryption_method: u32,
    pub vmk_entries: Vec<VmkEntry>,
    pub recovery_key_guids: Vec<String>,
    /// 解析过程中的非致命说明（例如 metadata size copy 不一致、GUID 全零被跳过）。
    pub notes: Vec<String>,
}

impl FveMetadata {
    pub fn encryption_method_label(&self) -> String {
        encryption_method_label(self.encryption_method)
    }
}

/// 一个 `-FVE-FS-` 命中的上下文与解析结果。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FveVolume {
    pub signature_offset: u64,
    pub volume_header_offset: Option<u64>,
    pub boot_entry: Option<[u8; 3]>,
    pub status: ParseStatus,
    pub parse_basis: ParseBasis,
    pub metadata: Option<FveMetadata>,
    pub error: Option<String>,
    pub limitations: Vec<String>,
}

/// 解析一个 `-FVE-FS-` 命中。读取错误与畸形元数据都转成结果内的状态/说明，
/// 不 panic；只有调用方取消或扫描短读才作为错误向上返回。
pub fn parse_fve_volume<R: ImageReader + ?Sized>(reader: &R, signature_offset: u64) -> FveVolume {
    let mut volume = FveVolume {
        signature_offset,
        volume_header_offset: None,
        boot_entry: None,
        status: ParseStatus::NotBootHeader,
        parse_basis: ParseBasis::None,
        metadata: None,
        error: None,
        limitations: Vec::new(),
    };

    if signature_offset < 3 {
        volume.error = Some("签名距文件开头不足 3 字节，无法定位 BitLocker 卷头".to_string());
        return volume;
    }
    let volume_header_offset = signature_offset - 3;
    volume.volume_header_offset = Some(volume_header_offset);

    let boot = match read_exact_at(reader, volume_header_offset, 3) {
        Ok(bytes) => bytes,
        Err(error) => {
            volume.status = ParseStatus::InvalidMetadata;
            volume.error = Some(format!("读取卷头前 3 字节失败：{error}"));
            return volume;
        }
    };
    let boot_entry = [boot[0], boot[1], boot[2]];
    volume.boot_entry = Some(boot_entry);

    if !(boot_entry[0] == 0xEB && boot_entry[2] == 0x90) {
        // 不是启动卷头前缀：命中本身可能是 FVE 元数据块（同一签名），
        // 尝试把它当作独立元数据块解析；所有结构校验仍然生效。
        let probe = probe_metadata_block(reader, signature_offset);
        if let Some(metadata) = probe.metadata {
            volume.status = ParseStatus::Parsed;
            volume.parse_basis = ParseBasis::MetadataBlock;
            volume.limitations.push(
                "命中处前 3 字节不是 EB ?? 90；按 -FVE-FS- 元数据块直接解析，未确认启动卷头"
                    .to_string(),
            );
            volume.limitations.extend(metadata.notes.iter().cloned());
            if metadata.recovery_key_guids.is_empty() {
                volume.limitations.push(
                    "FVE 元数据中没有 protection type = 0x0800（恢复密码）的 VMK，恢复密钥 GUID 未解析；不猜测"
                        .to_string(),
                );
            }
            volume.metadata = Some(metadata);
            return volume;
        }

        volume.status = ParseStatus::NotBootHeader;
        volume.limitations.push(
            "命中处前 3 字节不是 EB ?? 90，可能是 FVE 元数据块或嵌入副本；未按 BitLocker 启动卷头解析"
                .to_string(),
        );
        if let Some(error) = probe.error {
            volume
                .limitations
                .push(format!("按独立元数据块直接解析也未通过：{error}"));
        }
        return volume;
    }

    volume.parse_basis = ParseBasis::BootHeader;

    let header = match read_exact_at(reader, volume_header_offset, VHD_FOOTER_SIZE as usize) {
        Ok(bytes) => bytes,
        Err(error) => {
            volume.status = ParseStatus::InvalidMetadata;
            volume.error = Some(format!("读取 512 字节 BitLocker 卷头失败：{error}"));
            return volume;
        }
    };

    let candidates = metadata_candidates(&header);
    if candidates.is_empty() {
        volume.status = ParseStatus::NoMetadata;
        volume.error = Some("卷头 176/184/192 字节处的 FVE 元数据块偏移均为 0".to_string());
        return volume;
    }

    let mut found_block_signature = false;
    let mut parsed_blocks: Vec<FveMetadata> = Vec::new();
    let mut probed_offsets: Vec<u64> = Vec::new();

    for (field_offset, relative) in candidates {
        let block_offset = match volume_header_offset.checked_add(relative) {
            Some(offset) => offset,
            None => {
                volume.limitations.push(format!(
                    "卷头 +{field_offset} 字节记录元数据块偏移 0x{relative:X} 溢出，未解析"
                ));
                continue;
            }
        };
        if !probed_offsets.contains(&block_offset) {
            probed_offsets.push(block_offset);
        } else {
            continue;
        }

        let probe = probe_metadata_block(reader, block_offset);
        found_block_signature |= probe.found_signature;
        if let Some(metadata) = probe.metadata {
            parsed_blocks.push(metadata);
        } else if let Some(error) = probe.error {
            volume.limitations.push(format!(
                "卷头 +{field_offset} 字节记录的元数据块 @0x{block_offset:X} 未解析：{error}"
            ));
        }
    }

    if parsed_blocks.is_empty() {
        if found_block_signature {
            volume.status = ParseStatus::InvalidMetadata;
            volume.error = Some(
                "找到了 -FVE-FS- 元数据块签名，但元数据头或条目未通过长度/版本校验".to_string(),
            );
        } else {
            volume.status = ParseStatus::NoMetadata;
            volume.error = Some("卷头记录的元数据块偏移处没有 -FVE-FS- 块签名".to_string());
        }
        return volume;
    }

    parsed_blocks.sort_by_key(|metadata| {
        (
            metadata.recovery_key_guids.len(),
            metadata.vmk_entries.len(),
        )
    });
    let chosen = parsed_blocks.pop().expect("non-empty");
    if !parsed_blocks.is_empty() {
        volume.limitations.push(format!(
            "解析到 {} 个有效 FVE 元数据块，采用 @0x{:X} 的一个；其余块仅用于交叉核对",
            parsed_blocks.len() + 1,
            chosen.block_offset
        ));
    }

    volume.limitations.extend(chosen.notes.iter().cloned());
    if chosen.recovery_key_guids.is_empty() {
        volume.limitations.push(
            "FVE 元数据中没有 protection type = 0x0800（恢复密码）的 VMK，恢复密钥 GUID 未解析；不猜测"
                .to_string(),
        );
    }

    volume.status = ParseStatus::Parsed;
    volume.metadata = Some(chosen);
    volume
}

/// 卷头中非零的元数据块候选（字段偏移, 相对卷头偏移）。
fn metadata_candidates(header: &[u8]) -> Vec<(usize, u64)> {
    let mut candidates = Vec::new();
    for field_offset in METADATA_OFFSET_FIELDS {
        let relative = le_u64(header, field_offset);
        if relative != 0 {
            candidates.push((field_offset, relative));
        }
    }
    candidates
}

struct MetadataProbe {
    found_signature: bool,
    metadata: Option<FveMetadata>,
    error: Option<String>,
}

/// 探测一个元数据块偏移；所有读取与结构检查都有界。
fn probe_metadata_block<R: ImageReader + ?Sized>(reader: &R, block_offset: u64) -> MetadataProbe {
    let mut probe = MetadataProbe {
        found_signature: false,
        metadata: None,
        error: None,
    };

    if block_offset >= reader.size() {
        probe.error = Some("元数据块偏移超出文件大小".to_string());
        return probe;
    }

    let block_header =
        match read_exact_at(reader, block_offset, METADATA_BLOCK_HEADER_SIZE as usize) {
            Ok(bytes) => bytes,
            Err(error) => {
                probe.error = Some(error);
                return probe;
            }
        };
    if &block_header[..FVE_SIGNATURE.len()] != FVE_SIGNATURE {
        probe.error = Some("该偏移不是 -FVE-FS- 元数据块".to_string());
        return probe;
    }
    probe.found_signature = true;

    let block_version = le_u16(&block_header, 10);
    if !matches!(block_version, 1 | 2) {
        probe.error = Some(format!("不支持的 FVE 元数据块版本 {block_version}"));
        return probe;
    }

    let metadata_offset = match block_offset.checked_add(METADATA_BLOCK_HEADER_SIZE) {
        Some(offset) => offset,
        None => {
            probe.error = Some("FVE 元数据头偏移溢出".to_string());
            return probe;
        }
    };
    let metadata_header =
        match read_exact_at(reader, metadata_offset, METADATA_HEADER_SIZE as usize) {
            Ok(bytes) => bytes,
            Err(error) => {
                probe.error = Some(format!("读取 FVE 元数据头失败：{error}"));
                return probe;
            }
        };

    let metadata_size = le_u32(&metadata_header, 0);
    let metadata_version = le_u32(&metadata_header, 4);
    let metadata_header_size = le_u32(&metadata_header, 8);
    let metadata_size_copy = le_u32(&metadata_header, 12);

    if metadata_version != 1 {
        probe.error = Some(format!("不支持的 FVE 元数据头版本 {metadata_version}"));
        return probe;
    }
    if metadata_header_size < METADATA_HEADER_SIZE {
        probe.error = Some(format!(
            "FVE 元数据头长度 {metadata_header_size} 小于 {METADATA_HEADER_SIZE}"
        ));
        return probe;
    }
    if metadata_header_size > metadata_size {
        probe.error = Some(format!(
            "FVE 元数据头长度 {metadata_header_size} 大于元数据总长 {metadata_size}"
        ));
        return probe;
    }
    if metadata_size > MAX_METADATA_BYTES {
        probe.error = Some(format!(
            "FVE 元数据长度 {metadata_size} 超过上限 {MAX_METADATA_BYTES}"
        ));
        return probe;
    }
    if metadata_size < metadata_header_size.saturating_add(8) {
        probe.error = Some(format!("FVE 元数据长度 {metadata_size} 不足以容纳一个条目"));
        return probe;
    }
    let metadata_end = metadata_offset
        .checked_add(u64::from(metadata_size))
        .filter(|end| *end <= reader.size());
    if metadata_end.is_none() {
        probe.error = Some(format!(
            "FVE 元数据 @0x{metadata_offset:X} 长度 {metadata_size} 超出文件大小"
        ));
        return probe;
    }

    let metadata_bytes = match read_exact_at(reader, metadata_offset, metadata_size as usize) {
        Ok(bytes) => bytes,
        Err(error) => {
            probe.error = Some(format!("读取 FVE 元数据失败：{error}"));
            return probe;
        }
    };

    let mut notes = Vec::new();
    if metadata_size_copy != metadata_size {
        notes.push(format!(
            "FVE 元数据长度字段与副本不一致（{metadata_size} / {metadata_size_copy}），按主字段解析"
        ));
    }

    let vmk_entries = parse_vmk_entries(
        &metadata_bytes,
        metadata_header_size,
        metadata_size,
        &mut notes,
    );
    let mut recovery_key_guids = Vec::new();
    for entry in &vmk_entries {
        if entry.is_recovery_key && !recovery_key_guids.contains(&entry.guid) {
            recovery_key_guids.push(entry.guid.clone());
        }
    }

    probe.metadata = Some(FveMetadata {
        block_offset,
        block_version,
        metadata_offset,
        metadata_size,
        volume_id: format_guid(&metadata_bytes[16..32]),
        encryption_method: le_u32(&metadata_bytes, 36),
        vmk_entries,
        recovery_key_guids,
        notes,
    });
    probe
}

/// 解析元数据头之后的条目数组。只收集 VMK（entry type 0x0002 / value 0x0008），
/// 其余类型按 entry size 跳过。
fn parse_vmk_entries(
    metadata: &[u8],
    header_size: u32,
    metadata_size: u32,
    notes: &mut Vec<String>,
) -> Vec<VmkEntry> {
    let mut entries = Vec::new();
    let mut seen: Vec<(String, u16)> = Vec::new();
    let end = metadata_size as usize;
    let mut position = header_size as usize;

    while position + 8 <= end {
        let entry_size = le_u16(metadata, position) as usize;
        let entry_type = le_u16(metadata, position + 2);
        let value_type = le_u16(metadata, position + 4);

        if entry_size == 0 {
            break;
        }
        if entry_size < 8 || position + entry_size > end {
            notes.push(format!(
                "FVE 元数据条目 @0x{position:X} 长度 {entry_size} 越界，停止解析条目"
            ));
            break;
        }

        if entry_type == ENTRY_TYPE_VMK && value_type == VALUE_TYPE_VMK {
            let data = &metadata[position + 8..position + entry_size];
            if data.len() < 28 {
                notes.push(format!(
                    "FVE VMK 条目 @0x{position:X} 数据长度 {} 小于 28，跳过",
                    data.len()
                ));
            } else {
                let guid_bytes = &data[..16];
                let protection_type = le_u16(data, 26);
                if guid_bytes.iter().all(|byte| *byte == 0) {
                    notes.push(format!(
                        "FVE VMK 条目 @0x{position:X} 的 GUID 全零，已跳过（不猜测）"
                    ));
                } else if let Some(guid) = format_guid(guid_bytes) {
                    let key = (guid.clone(), protection_type);
                    if !seen.contains(&key) {
                        seen.push(key);
                        entries.push(VmkEntry {
                            guid,
                            protection_type,
                            is_recovery_key: protection_type == PROTECTION_TYPE_RECOVERY_PASSWORD,
                        });
                        if entries.len() >= MAX_VMK_ENTRIES {
                            notes.push(format!(
                                "FVE VMK 条目达到上限 {MAX_VMK_ENTRIES}，其余条目未解析"
                            ));
                            break;
                        }
                    }
                }
            }
        }
        position += entry_size;
    }

    entries
}

/// GUID 的人类可读大写形式：前三个字段按小端读取，尾部 8 字节按原序。
pub fn format_guid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 16 {
        return None;
    }
    let data1 = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let data2 = u16::from_le_bytes([bytes[4], bytes[5]]);
    let data3 = u16::from_le_bytes([bytes[6], bytes[7]]);
    let tail = &bytes[8..16];
    Some(format!(
        "{data1:08X}-{data2:04X}-{data3:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        tail[0], tail[1], tail[2], tail[3], tail[4], tail[5], tail[6], tail[7]
    ))
}

/// VMK protection type 的可读标签。
pub fn protection_type_label(protection_type: u16) -> String {
    match protection_type {
        0x0000 => "clear key（未受保护）".to_string(),
        0x0100 => "TPM".to_string(),
        0x0200 => "启动密钥".to_string(),
        0x0500 => "TPM + PIN".to_string(),
        0x0800 => "恢复密码".to_string(),
        0x2000 => "密码".to_string(),
        other => format!("未知 (0x{other:04X})"),
    }
}

/// FVE 元数据头 encryption method 的可读标签。
pub fn encryption_method_label(method: u32) -> String {
    match method {
        0x0000 => "未加密/外部密钥 (0x0000)".to_string(),
        0x1000 | 0x1001 => format!("Stretch key (0x{method:04X})"),
        0x2000..=0x2005 => format!("AES-256-CCM (0x{method:04X})"),
        0x8000 => "AES-128-CBC + Elephant Diffuser (0x8000)".to_string(),
        0x8001 => "AES-256-CBC + Elephant Diffuser (0x8001)".to_string(),
        0x8002 => "AES-128-CBC (0x8002)".to_string(),
        0x8003 => "AES-256-CBC (0x8003)".to_string(),
        0x8004 => "AES-128-XTS (0x8004)".to_string(),
        0x8005 => "AES-256-XTS (0x8005)".to_string(),
        other => format!("未知 (0x{other:04X})"),
    }
}

/// 大写十六进制，无分隔符。
pub fn hex_upper(bytes: &[u8]) -> String {
    let mut text = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut text, "{byte:02X}");
    }
    text
}

/// 三字节引导入口的展示形式，如 `EB 58 90`。
pub fn boot_entry_hex(bytes: [u8; 3]) -> String {
    format!("{:02X} {:02X} {:02X}", bytes[0], bytes[1], bytes[2])
}

fn read_exact_at<R: ImageReader + ?Sized>(
    reader: &R,
    offset: u64,
    length: usize,
) -> Result<Vec<u8>, String> {
    let data = reader.read_at(offset, length)?;
    if data.len() < length {
        return Err(format!(
            "偏移 0x{offset:X} 请求 {length} 字节，只读到 {} 字节",
            data.len()
        ));
    }
    Ok(data)
}

fn le_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
}

fn le_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn le_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

fn be_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ])
}

fn be_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
        bytes[offset + 4],
        bytes[offset + 5],
        bytes[offset + 6],
        bytes[offset + 7],
    ])
}

/// 解码 VHDX creator：UTF-16LE，遇到 NUL 停止，非法代理用替换字符。
fn decode_utf16le(bytes: &[u8]) -> String {
    let mut units = Vec::new();
    for pair in bytes.chunks_exact(2) {
        let unit = u16::from_le_bytes([pair[0], pair[1]]);
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units).trim().to_string()
}

#[cfg(test)]
pub(crate) mod fixtures {
    use super::*;

    pub(crate) const TEST_VOLUME_OFFSET: u64 = 1024;
    pub(crate) const TEST_METADATA_RELATIVE_OFFSET: u64 = 4096;
    pub(crate) const TEST_BLOCK_OFFSET: u64 = TEST_VOLUME_OFFSET + TEST_METADATA_RELATIVE_OFFSET;

    pub(crate) struct TestVmk {
        pub protection_type: u16,
        pub guid: [u8; 16],
    }

    pub(crate) fn recovery_vmk(guid: [u8; 16]) -> TestVmk {
        TestVmk {
            protection_type: PROTECTION_TYPE_RECOVERY_PASSWORD,
            guid,
        }
    }

    pub(crate) fn tpm_vmk(guid: [u8; 16]) -> TestVmk {
        TestVmk {
            protection_type: 0x0100,
            guid,
        }
    }

    /// 512 字节 VHD footer。unique id 固定为非零合成值。
    pub(crate) fn vhd_footer(disk_type: u32, current_size: u64) -> Vec<u8> {
        let mut footer = vec![0_u8; VHD_FOOTER_SIZE as usize];
        footer[0..8].copy_from_slice(VHD_COOKIE);
        footer[8..12].copy_from_slice(&2_u32.to_be_bytes());
        footer[12..16].copy_from_slice(&0x0001_0000_u32.to_be_bytes());
        footer[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
        footer[28..32].copy_from_slice(b"test");
        footer[40..48].copy_from_slice(&current_size.to_be_bytes());
        footer[48..56].copy_from_slice(&current_size.to_be_bytes());
        footer[60..64].copy_from_slice(&disk_type.to_be_bytes());
        footer[68..84].copy_from_slice(&[0x11; 16]);
        // VHD footer checksum：checksum 字段置 0 后所有字节求和，再取反。
        let sum: u32 = footer.iter().map(|byte| u32::from(*byte)).sum();
        footer[64..68].copy_from_slice(&(!sum).to_be_bytes());
        footer
    }

    /// 最小 VHDX 文件标识区（4 KiB），creator 以 UTF-16LE 写入。
    pub(crate) fn vhdx_identifier(creator: &str) -> Vec<u8> {
        let mut bytes = vec![0_u8; 4096];
        bytes[..8].copy_from_slice(VHDX_MAGIC);
        for (index, unit) in creator.encode_utf16().take(255).enumerate() {
            let offset = 8 + index * 2;
            bytes[offset..offset + 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    /// 合成 BitLocker 卷：512 字节卷头 + 4096 字节处的 FVE 元数据块。
    pub(crate) fn fve_volume(vmks: &[TestVmk]) -> Vec<u8> {
        fve_volume_at(TEST_METADATA_RELATIVE_OFFSET, 2, 1, vmks)
    }

    /// 可指定元数据相对偏移、块版本与元数据头版本的合成卷。
    pub(crate) fn fve_volume_at(
        metadata_relative_offset: u64,
        block_version: u16,
        metadata_header_version: u32,
        vmks: &[TestVmk],
    ) -> Vec<u8> {
        assert!(metadata_relative_offset >= 512);
        let block_offset = metadata_relative_offset as usize;
        let entry_size = 36_usize;
        let metadata_size = METADATA_HEADER_SIZE as usize + entry_size * vmks.len();
        let total = block_offset + METADATA_BLOCK_HEADER_SIZE as usize + metadata_size + 64;
        let mut bytes = vec![0_u8; total];

        bytes[0..3].copy_from_slice(&[0xEB, 0x58, 0x90]);
        bytes[3..11].copy_from_slice(FVE_SIGNATURE);
        bytes[160..176].copy_from_slice(&[0x42; 16]);
        bytes[176..184].copy_from_slice(&metadata_relative_offset.to_le_bytes());
        bytes[184..192].copy_from_slice(&0_u64.to_le_bytes());
        bytes[192..200].copy_from_slice(&0_u64.to_le_bytes());
        bytes[510..512].copy_from_slice(&[0x55, 0xAA]);

        bytes[block_offset..block_offset + 8].copy_from_slice(FVE_SIGNATURE);
        bytes[block_offset + 10..block_offset + 12].copy_from_slice(&block_version.to_le_bytes());
        bytes[block_offset + 32..block_offset + 40]
            .copy_from_slice(&metadata_relative_offset.to_le_bytes());

        let metadata_offset = block_offset + METADATA_BLOCK_HEADER_SIZE as usize;
        bytes[metadata_offset..metadata_offset + 4]
            .copy_from_slice(&(metadata_size as u32).to_le_bytes());
        bytes[metadata_offset + 4..metadata_offset + 8]
            .copy_from_slice(&metadata_header_version.to_le_bytes());
        bytes[metadata_offset + 8..metadata_offset + 12]
            .copy_from_slice(&METADATA_HEADER_SIZE.to_le_bytes());
        bytes[metadata_offset + 12..metadata_offset + 16]
            .copy_from_slice(&(metadata_size as u32).to_le_bytes());
        bytes[metadata_offset + 16..metadata_offset + 32].copy_from_slice(&[0x24; 16]);
        bytes[metadata_offset + 32..metadata_offset + 36].copy_from_slice(&1_u32.to_le_bytes());
        bytes[metadata_offset + 36..metadata_offset + 40]
            .copy_from_slice(&0x8005_u32.to_le_bytes());

        let mut position = metadata_offset + METADATA_HEADER_SIZE as usize;
        for vmk in vmks {
            bytes[position..position + 2].copy_from_slice(&(entry_size as u16).to_le_bytes());
            bytes[position + 2..position + 4].copy_from_slice(&ENTRY_TYPE_VMK.to_le_bytes());
            bytes[position + 4..position + 6].copy_from_slice(&VALUE_TYPE_VMK.to_le_bytes());
            bytes[position + 6..position + 8].copy_from_slice(&1_u16.to_le_bytes());
            bytes[position + 8..position + 24].copy_from_slice(&vmk.guid);
            bytes[position + 34..position + 36].copy_from_slice(&vmk.protection_type.to_le_bytes());
            position += entry_size;
        }

        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::fixtures::{self, TestVmk};
    use super::*;

    struct SliceReader<'a>(&'a [u8]);

    impl ImageReader for SliceReader<'_> {
        fn size(&self) -> u64 {
            self.0.len() as u64
        }

        fn read_at(&self, offset: u64, length: usize) -> Result<Vec<u8>, String> {
            if offset > self.0.len() as u64 {
                return Ok(Vec::new());
            }
            let start = offset as usize;
            let end = start.saturating_add(length).min(self.0.len());
            Ok(self.0[start..end].to_vec())
        }
    }

    fn read(bytes: &[u8]) -> SliceReader<'_> {
        SliceReader(bytes)
    }

    fn test_guid(seed: u8) -> [u8; 16] {
        let mut guid = [seed; 16];
        guid[0] = 0x11;
        guid[1] = 0x22;
        guid[2] = 0x33;
        guid[3] = 0x44;
        guid[4] = 0x55;
        guid[5] = 0x66;
        guid[6] = 0x77;
        guid[7] = 0x88;
        guid
    }

    #[test]
    fn guid_formats_first_fields_little_endian() {
        let mut bytes = [0_u8; 16];
        bytes[0..4].copy_from_slice(&0x1122_3344_u32.to_le_bytes());
        bytes[4..6].copy_from_slice(&0x5566_u16.to_le_bytes());
        bytes[6..8].copy_from_slice(&0x7788_u16.to_le_bytes());
        bytes[8..16].copy_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]);
        assert_eq!(
            format_guid(&bytes).as_deref(),
            Some("11223344-5566-7788-AABB-CCDDEEFF0011")
        );
        assert_eq!(format_guid(&bytes[..15]), None);
    }

    #[test]
    fn vhd_footer_is_detected_at_file_tail() {
        let footer = fixtures::vhd_footer(3, 1024 * 1024);
        let format = detect_format(4096, &[], Some(&footer));
        assert_eq!(format.format, Format::Vhd);
        assert_eq!(format.signature(), Some("conectix"));
        assert_eq!(format.signature_offset, Some(4096 - 512));
        let vhd = format.vhd.expect("vhd info");
        assert_eq!(vhd.footer_offset, 4096 - 512);
        assert_eq!(vhd.disk_type, 3);
        assert_eq!(vhd.disk_type_label(), "动态磁盘");
        assert_eq!(vhd.current_size, 1024 * 1024);
        assert_eq!(vhd.unique_id_hex, "11".repeat(16));
    }

    #[test]
    fn vhdx_magic_wins_and_creator_is_decoded() {
        let header = fixtures::vhdx_identifier("synthetic-vhdx");
        let format = detect_format(4096, &header, None);
        assert_eq!(format.format, Format::Vhdx);
        assert_eq!(format.signature(), Some("vhdxfile"));
        assert_eq!(format.signature_offset, Some(0));
        assert_eq!(format.vhdx.expect("vhdx info").creator, "synthetic-vhdx");
        assert!(format.vhd.is_none());
    }

    #[test]
    fn short_or_plain_files_are_unknown() {
        let format = detect_format(8, b"plain123", None);
        assert_eq!(format.format, Format::Unknown);
        assert_eq!(format.signature(), None);
        assert_eq!(format.signature_offset, None);
    }

    #[test]
    fn scan_finds_all_signatures_with_absolute_offsets() {
        let mut bytes = vec![0_u8; 256];
        bytes[5..13].copy_from_slice(FVE_SIGNATURE);
        bytes[100..108].copy_from_slice(FVE_SIGNATURE);
        let outcome = scan_for_signatures(&read(&bytes), 32, 16, || Ok(())).expect("scan succeeds");
        assert_eq!(outcome.offsets, vec![5, 100]);
        assert_eq!(outcome.bytes_scanned, 256);
        assert_eq!(outcome.scan_limit, 256);
        assert!(!outcome.truncated);
        assert!(!outcome.hit_limit_reached);
    }

    #[test]
    fn scan_crosses_chunk_boundary_without_loss_or_duplicates() {
        let mut bytes = vec![0_u8; 64];
        // 8 字节签名从第 12 字节开始，跨过 16 字节的块边界。
        bytes[12..20].copy_from_slice(FVE_SIGNATURE);
        bytes[40..48].copy_from_slice(FVE_SIGNATURE);
        let outcome = scan_for_signatures_with_limit(&read(&bytes), 64, 16, 16, || Ok(()))
            .expect("scan succeeds");
        assert_eq!(outcome.offsets, vec![12, 40]);
        assert_eq!(outcome.bytes_scanned, 64);
    }

    #[test]
    fn scan_respects_hit_limit_and_scan_limit() {
        let mut bytes = vec![0_u8; 128];
        for offset in [0_usize, 16, 32] {
            bytes[offset..offset + 8].copy_from_slice(FVE_SIGNATURE);
        }
        let outcome = scan_for_signatures_with_limit(&read(&bytes), 128, 16, 2, || Ok(()))
            .expect("scan succeeds");
        assert_eq!(outcome.offsets.len(), 2);
        assert!(outcome.hit_limit_reached);
        assert!(!outcome.truncated);

        let outcome = scan_for_signatures_with_limit(&read(&bytes), 64, 32, 16, || Ok(()))
            .expect("scan succeeds");
        assert_eq!(outcome.offsets, vec![0, 16, 32]);
        assert_eq!(outcome.bytes_scanned, 64);
        assert!(outcome.truncated);
        assert!(!outcome.hit_limit_reached);
    }

    #[test]
    fn scan_empty_file_is_zero_hits() {
        let outcome = scan_for_signatures(&read(&[]), 32, 16, || Ok(())).expect("scan succeeds");
        assert!(outcome.offsets.is_empty());
        assert_eq!(outcome.bytes_scanned, 0);
        assert_eq!(outcome.scan_limit, 0);
    }

    #[test]
    fn scan_reports_short_reads_instead_of_skipping() {
        struct ShortReader;
        impl ImageReader for ShortReader {
            fn size(&self) -> u64 {
                100
            }

            fn read_at(&self, _offset: u64, length: usize) -> Result<Vec<u8>, String> {
                Ok(vec![0_u8; length.saturating_sub(1)])
            }
        }
        let error =
            scan_for_signatures(&ShortReader, 16, 16, || Ok(())).expect_err("short read must fail");
        assert!(error.contains("只读到"));
    }

    #[test]
    fn scan_propagates_cancellation() {
        let bytes = vec![0_u8; 64];
        let error = scan_for_signatures(&read(&bytes), 16, 16, || Err("cancelled".to_string()))
            .expect_err("cancelled");
        assert_eq!(error, "cancelled");
    }

    #[test]
    fn parse_fve_volume_extracts_recovery_guid_only_from_recovery_vmk() {
        let recovery = test_guid(0xAA);
        let tpm = test_guid(0xBB);
        let bytes =
            fixtures::fve_volume(&[fixtures::tpm_vmk(tpm), fixtures::recovery_vmk(recovery)]);
        let volume = parse_fve_volume(&read(&bytes), 3);
        assert_eq!(volume.status, ParseStatus::Parsed);
        assert_eq!(volume.volume_header_offset, Some(0));
        assert_eq!(volume.boot_entry, Some([0xEB, 0x58, 0x90]));

        let metadata = volume.metadata.expect("metadata");
        assert_eq!(
            metadata.block_offset,
            fixtures::TEST_METADATA_RELATIVE_OFFSET
        );
        assert_eq!(metadata.block_version, 2);
        assert_eq!(metadata.metadata_size as usize, 48 + 36 * 2);
        assert_eq!(metadata.encryption_method, 0x8005);
        assert_eq!(
            metadata.volume_id.as_deref(),
            Some("24242424-2424-2424-2424-242424242424")
        );
        assert_eq!(metadata.vmk_entries.len(), 2);
        assert_eq!(
            metadata.recovery_key_guids,
            vec![format_guid(&recovery).expect("guid")]
        );
        assert_eq!(metadata.vmk_entries[0].protection_type, 0x0100);
        assert!(!metadata.vmk_entries[0].is_recovery_key);
        assert_eq!(metadata.vmk_entries[1].protection_type, 0x0800);
        assert!(metadata.vmk_entries[1].is_recovery_key);
    }

    #[test]
    fn parse_fve_volume_without_recovery_vmk_reports_limitation() {
        let bytes = fixtures::fve_volume(&[fixtures::tpm_vmk(test_guid(0xCC))]);
        let volume = parse_fve_volume(&read(&bytes), 3);
        assert_eq!(volume.status, ParseStatus::Parsed);
        assert!(volume
            .metadata
            .expect("metadata")
            .recovery_key_guids
            .is_empty());
        assert!(volume
            .limitations
            .iter()
            .any(|note| note.contains("0x0800") && note.contains("未解析")));
    }

    #[test]
    fn metadata_block_hit_is_parsed_without_boot_header() {
        let recovery = test_guid(0xA1);
        let bytes = fixtures::fve_volume(&[fixtures::recovery_vmk(recovery)]);
        let block_offset = fixtures::TEST_METADATA_RELATIVE_OFFSET;
        let volume = parse_fve_volume(&read(&bytes), block_offset);
        assert_eq!(volume.status, ParseStatus::Parsed);
        assert_eq!(volume.parse_basis, ParseBasis::MetadataBlock);
        let metadata = volume.metadata.expect("metadata");
        assert_eq!(metadata.block_offset, block_offset);
        assert_eq!(
            metadata.recovery_key_guids,
            vec![format_guid(&recovery).expect("guid")]
        );
        assert!(volume
            .limitations
            .iter()
            .any(|note| note.contains("独立元数据块") || note.contains("未确认启动卷头")));
    }

    #[test]
    fn parse_fve_volume_rejects_non_boot_header_hits() {
        let bytes = fixtures::fve_volume(&[fixtures::recovery_vmk(test_guid(0xDD))]);
        // 签名在文件偏移 3，但把前 3 字节改成普通数据。
        let mut non_boot = bytes.clone();
        non_boot[0..3].copy_from_slice(&[0, 0, 0]);
        let volume = parse_fve_volume(&read(&non_boot), 3);
        assert_eq!(volume.status, ParseStatus::NotBootHeader);
        assert!(volume.metadata.is_none());
        assert!(volume
            .limitations
            .iter()
            .any(|note| note.contains("EB ?? 90")));

        let volume = parse_fve_volume(&read(&bytes), 0);
        assert_eq!(volume.status, ParseStatus::NotBootHeader);
        assert!(volume.volume_header_offset.is_none());
    }

    #[test]
    fn parse_fve_volume_reports_missing_and_out_of_bounds_metadata() {
        let mut bytes = fixtures::fve_volume(&[fixtures::recovery_vmk(test_guid(0xEE))]);
        bytes[176..184].copy_from_slice(&0_u64.to_le_bytes());
        bytes[184..192].copy_from_slice(&0_u64.to_le_bytes());
        bytes[192..200].copy_from_slice(&0_u64.to_le_bytes());
        let volume = parse_fve_volume(&read(&bytes), 3);
        assert_eq!(volume.status, ParseStatus::NoMetadata);
        assert!(volume
            .error
            .as_deref()
            .is_some_and(|error| error.contains("均为 0")));

        let mut bytes = fixtures::fve_volume(&[fixtures::recovery_vmk(test_guid(0xEF))]);
        bytes[176..184].copy_from_slice(&u64::MAX.to_le_bytes());
        let volume = parse_fve_volume(&read(&bytes), 3);
        assert_eq!(volume.status, ParseStatus::NoMetadata);
        assert!(
            volume.limitations.iter().any(|note| note.contains("溢出"))
                || volume.error.as_deref().is_some()
        );
    }

    #[test]
    fn parse_fve_volume_reports_invalid_metadata_header() {
        let bytes = fixtures::fve_volume_at(
            fixtures::TEST_METADATA_RELATIVE_OFFSET,
            2,
            2,
            &[fixtures::recovery_vmk(test_guid(0xF0))],
        );
        let volume = parse_fve_volume(&read(&bytes), 3);
        assert_eq!(volume.status, ParseStatus::InvalidMetadata);
        assert!(volume.metadata.is_none());
        assert!(volume
            .limitations
            .iter()
            .any(|note| note.contains("元数据头版本 2")));
    }

    #[test]
    fn parse_fve_volume_handles_truncated_metadata_without_panic() {
        let bytes = fixtures::fve_volume(&[fixtures::recovery_vmk(test_guid(0xF1))]);
        let truncated = &bytes[..fixtures::TEST_METADATA_RELATIVE_OFFSET as usize + 64 + 20];
        let volume = parse_fve_volume(&read(truncated), 3);
        assert_eq!(volume.status, ParseStatus::InvalidMetadata);
        assert!(volume.metadata.is_none());
        assert!(!volume.limitations.is_empty());
    }

    #[test]
    fn parse_fve_volume_skips_zero_guid_without_guessing() {
        let bytes = fixtures::fve_volume(&[TestVmk {
            protection_type: PROTECTION_TYPE_RECOVERY_PASSWORD,
            guid: [0_u8; 16],
        }]);
        let volume = parse_fve_volume(&read(&bytes), 3);
        assert_eq!(volume.status, ParseStatus::Parsed);
        assert!(volume
            .metadata
            .expect("metadata")
            .recovery_key_guids
            .is_empty());
        assert!(volume
            .limitations
            .iter()
            .any(|note| note.contains("GUID 全零")));
    }

    #[test]
    fn fve_signature_bytes_are_exact() {
        assert_eq!(
            FVE_SIGNATURE,
            &[0x2D, 0x46, 0x56, 0x45, 0x2D, 0x46, 0x53, 0x2D]
        );
        assert_eq!(VHD_COOKIE, b"conectix");
        assert_eq!(VHDX_MAGIC, b"vhdxfile");
    }

    #[test]
    fn protection_and_encryption_labels_are_stable() {
        assert_eq!(protection_type_label(0x0800), "恢复密码");
        assert_eq!(protection_type_label(0x0100), "TPM");
        assert!(protection_type_label(0x9999).contains("0x9999"));
        assert_eq!(encryption_method_label(0x8005), "AES-256-XTS (0x8005)");
        assert_eq!(encryption_method_label(0x8004), "AES-128-XTS (0x8004)");
        assert!(encryption_method_label(0x9999).contains("未知"));
    }

    #[test]
    fn boot_entry_hex_is_readable() {
        assert_eq!(boot_entry_hex([0xEB, 0x58, 0x90]), "EB 58 90");
        assert_eq!(hex_upper(&[0x2D, 0x46, 0x56]), "2D4656");
    }
}
