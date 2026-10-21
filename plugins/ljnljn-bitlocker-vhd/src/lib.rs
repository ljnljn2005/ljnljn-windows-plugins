//! BitLocker signatures and recovery-key GUIDs in VHD/VHDX images (LPP v2).
//!
//! The byte parser is unchanged from the LPP v1 plugin: VHD footer / VHDX
//! header detection, an 8 GiB `-FVE-FS-` scan in 4 MiB chunks with a 7 byte
//! overlap, Windows 7+ FVE boot-header parsing and an independent
//! metadata-block fallback. Only VMK entries with protection type `0x0800`
//! (recovery password) yield a recovery-key GUID; anything else is reported
//! as a limitation instead of a guess.
//!
//! Emit shape: one `bitlocker.image` summary, one `bitlocker.hit` per
//! `-FVE-FS-` offset and one `bitlocker.vmk` per parsed VMK entry. The plugin
//! never decrypts, mounts or executes image content.

mod parser;

#[cfg(test)]
mod tests;

use lovelycarve_plugin::{export_plugin, Error, FileRef, Plugin, Record, Result, Run};

/// Static limitations; dynamic ones are appended per run.
const STATIC_LIMITATIONS: [&str; 6] = [
    "只读识别：不解密、不挂载、不执行 VHD/VHDX 内容，不提取 48 位恢复密钥数字密码，不联网。",
    "格式识别只检查 VHDX 文件头 vhdxfile 与 VHD 文件尾 512 字节的 conectix 签名；不验证 VHD/VHDX 校验和，不解析动态块、差异盘链或分区表。",
    "BitLocker 签名按文件绝对偏移扫描并输出；不解析 VHD/VHDX 分区表，因此不判断签名属于哪个分区或卷。",
    "FVE 元数据优先按 Windows 7+ 启动卷头布局（元数据块偏移 176/184/192，要求命中前 3 字节为 EB ?? 90）解析；前缀不符时仅尝试把命中处当作独立元数据块直接解析。Vista 卷头与 BitLocker To Go FAT（MSWIN4.1）布局未解析。",
    "恢复密钥 GUID 只从 FVE VMK 条目中 protection type = 0x0800 的 16 字节标识符读取；不从文件名、txt、注册表或外部恢复密钥文件推断/匹配。",
    "签名存在只说明字节模式命中，可能是真实 BitLocker 卷头、元数据副本、残留或伪造；未命中也不排除签名位于扫描上限之外。",
];

#[derive(Record)]
#[record(
    id = "bitlocker.image",
    label = "BitLocker 镜像识别",
    title = "{file_name}"
)]
struct BitlockerImage {
    #[field(label = "来源文件", key)]
    file_name: String,
    #[field(label = "MIME")]
    mime: Option<String>,
    #[field(label = "文件大小", kind = "size")]
    file_size: u64,
    #[field(
        label = "格式",
        kind = "enum",
        choices = "vhd=VHD,vhdx=VHDX,unknown=未知"
    )]
    format: String,
    #[field(label = "格式标签")]
    format_label: String,
    #[field(label = "格式签名")]
    format_signature: Option<String>,
    #[field(label = "格式签名偏移")]
    format_signature_offset: Option<u64>,
    #[field(label = "是否命中签名")]
    encrypted: bool,
    #[field(
        label = "加密证据",
        kind = "enum",
        choices = "fve_signature=FVE 签名,none_in_scanned_range=扫描范围内未命中"
    )]
    encryption_evidence: String,
    #[field(label = "签名数")]
    signature_count: usize,
    #[field(label = "首个签名偏移")]
    first_signature_offset: Option<u64>,
    #[field(label = "恢复密钥 GUID")]
    recovery_key_guid: Option<String>,
    #[field(label = "恢复密钥 GUID 列表", kind = "list")]
    recovery_key_guids: Vec<String>,
    #[field(label = "已扫描字节", kind = "size")]
    scan_bytes: u64,
    #[field(label = "扫描上限", kind = "size")]
    scan_limit: u64,
    #[field(label = "扫描被上限截断")]
    scan_truncated: bool,
    #[field(label = "命中达到上限")]
    hit_limit_reached: bool,
    #[field(label = "VHD footer 偏移")]
    vhd_footer_offset: Option<u64>,
    #[field(label = "VHD 磁盘类型")]
    vhd_disk_type: Option<u32>,
    #[field(label = "VHD 磁盘类型标签")]
    vhd_disk_type_label: Option<String>,
    #[field(label = "VHD 当前大小", kind = "size")]
    vhd_current_size: Option<u64>,
    #[field(label = "VHD 唯一 ID")]
    vhd_unique_id_hex: Option<String>,
    #[field(label = "VHDX 创建者")]
    vhdx_creator: Option<String>,
    #[field(label = "限制说明", kind = "list")]
    limitations: Vec<String>,
}

#[derive(Record)]
#[record(
    id = "bitlocker.hit",
    label = "FVE 签名命中",
    title = "签名 @ {signature_offset}"
)]
struct BitlockerHit {
    #[field(label = "签名偏移", key)]
    signature_offset: u64,
    #[field(label = "卷头偏移")]
    volume_header_offset: Option<u64>,
    #[field(label = "引导入口")]
    boot_entry: Option<String>,
    #[field(
        label = "解析状态",
        kind = "enum",
        choices = "parsed=已解析,not_boot_header=非引导卷头,no_metadata=无元数据,invalid_metadata=元数据损坏"
    )]
    parse_status: String,
    #[field(
        label = "解析依据",
        kind = "enum",
        choices = "boot_header=启动卷头,metadata_block=独立元数据块,none=未解析"
    )]
    parse_basis: String,
    #[field(label = "元数据块偏移")]
    metadata_block_offset: Option<u64>,
    #[field(label = "元数据版本")]
    metadata_version: Option<u64>,
    #[field(label = "元数据大小")]
    metadata_size: Option<u64>,
    #[field(label = "元数据卷 ID")]
    metadata_volume_id: Option<String>,
    #[field(label = "加密方法")]
    encryption_method: Option<u64>,
    #[field(label = "加密方法标签")]
    encryption_method_label: Option<String>,
    #[field(label = "VMK 数")]
    vmk_count: usize,
    #[field(label = "恢复密钥 GUID 数")]
    recovery_key_guid_count: usize,
    #[field(label = "恢复密钥 GUID 列表", kind = "list")]
    recovery_key_guids: Vec<String>,
    #[field(label = "解析错误")]
    parse_error: Option<String>,
    #[field(label = "限制说明", kind = "list")]
    limitations: Vec<String>,
}

#[derive(Record)]
#[record(id = "bitlocker.vmk", label = "FVE VMK 条目", title = "{vmk_guid}")]
struct BitlockerVmk {
    #[field(label = "VMK GUID", key)]
    vmk_guid: String,
    #[field(label = "保护类型")]
    protection_type: u32,
    #[field(label = "保护类型标签")]
    protection_label: String,
    #[field(label = "是否恢复密钥")]
    is_recovery_key: bool,
    #[field(label = "签名偏移")]
    signature_offset: u64,
    #[field(label = "元数据块偏移")]
    metadata_block_offset: u64,
    #[field(label = "条目序号")]
    index: usize,
}

/// Adapts the SDK's read-only file handle to the parser's random-access trait.
struct Reader<'a>(&'a FileRef);

impl parser::ImageReader for Reader<'_> {
    fn size(&self) -> u64 {
        self.0.size()
    }

    fn read_at(&self, offset: u64, length: usize) -> std::result::Result<Vec<u8>, String> {
        self.0
            .read_at(offset, length)
            .map_err(|error| error.to_string())
    }
}

fn push_unique(notes: &mut Vec<String>, note: impl Into<String>) {
    let note = note.into();
    if !note.is_empty() && !notes.contains(&note) {
        notes.push(note);
    }
}

fn collect_recovery_guids(volumes: &[parser::FveVolume]) -> Vec<String> {
    let mut guids = Vec::new();
    for volume in volumes {
        if let Some(metadata) = &volume.metadata {
            for guid in &metadata.recovery_key_guids {
                if !guids.contains(guid) {
                    guids.push(guid.clone());
                }
            }
        }
    }
    guids
}

fn collect_limitations(
    file_size: u64,
    format: &parser::FormatInfo,
    scan: &parser::ScanOutcome,
    volumes: &[parser::FveVolume],
    recovery_guids: &[String],
) -> Vec<String> {
    let mut notes: Vec<String> = STATIC_LIMITATIONS
        .iter()
        .map(|note| (*note).to_string())
        .collect();

    if file_size < parser::VHD_FOOTER_SIZE {
        push_unique(
            &mut notes,
            format!(
                "文件只有 {file_size} 字节，小于 VHD footer 的 512 字节，无法检查 VHD 文件尾签名"
            ),
        );
    }
    if format.format == parser::Format::Unknown {
        push_unique(
            &mut notes,
            "未识别为 VHD（文件尾 conectix）或 VHDX（文件头 vhdxfile）；仍按原始字节扫描 FVE 签名。"
                .to_string(),
        );
    }
    if scan.truncated {
        push_unique(
            &mut notes,
            format!(
                "文件 {file_size} 字节，只扫描前 {} 字节（扫描上限 {} 字节）；未扫描区域的签名与 GUID 未知。",
                scan.scan_limit,
                parser::MAX_SCAN_BYTES
            ),
        );
    }
    if scan.hit_limit_reached {
        push_unique(
            &mut notes,
            format!(
                "FVE 签名命中达到上限 {} 个，扫描提前停止；后续偏移未列出。",
                parser::MAX_SIGNATURE_HITS
            ),
        );
    }
    if scan.offsets.is_empty() {
        push_unique(
            &mut notes,
            format!(
                "已扫描的 {} 字节内没有发现 -FVE-FS- 签名；这不能证明镜像未加密。",
                scan.bytes_scanned
            ),
        );
    }
    if !scan.offsets.is_empty() && recovery_guids.is_empty() {
        push_unique(
            &mut notes,
            "已命中 -FVE-FS- 签名，但没有解析出恢复密钥 GUID；逐条查看命中的 parse_status 与 limitations，未做任何猜测。"
                .to_string(),
        );
    }
    if recovery_guids.len() > 1 {
        push_unique(
            &mut notes,
            format!(
                "解析到 {} 个不同的恢复密钥 GUID，未判断哪一个对应目标恢复密钥文件；已全部列出。",
                recovery_guids.len()
            ),
        );
    }

    for volume in volumes {
        let reference = format!("@0x{:X}", volume.signature_offset);
        for note in &volume.limitations {
            push_unique(&mut notes, format!("{reference}：{note}"));
        }
        if let Some(error) = &volume.error {
            push_unique(&mut notes, format!("{reference}：{error}"));
        }
    }
    notes
}

fn emit_image(
    run: &Run,
    file: &FileRef,
    format: &parser::FormatInfo,
    scan: &parser::ScanOutcome,
    recovery_guids: &[String],
    limitations: &[String],
) -> Result<()> {
    let encrypted = !scan.offsets.is_empty();
    let mut record = BitlockerImage {
        file_name: file.name().to_owned(),
        mime: file.mime().map(str::to_owned),
        file_size: file.size(),
        format: format.format.as_str().to_owned(),
        format_label: format.format.label().to_owned(),
        format_signature: format.signature().map(str::to_owned),
        format_signature_offset: format.signature_offset,
        encrypted,
        encryption_evidence: if encrypted {
            "fve_signature".to_owned()
        } else {
            "none_in_scanned_range".to_owned()
        },
        signature_count: scan.offsets.len(),
        first_signature_offset: scan.offsets.first().copied(),
        recovery_key_guid: recovery_guids.first().cloned(),
        recovery_key_guids: recovery_guids.to_vec(),
        scan_bytes: scan.bytes_scanned,
        scan_limit: scan.scan_limit,
        scan_truncated: scan.truncated,
        hit_limit_reached: scan.hit_limit_reached,
        vhd_footer_offset: None,
        vhd_disk_type: None,
        vhd_disk_type_label: None,
        vhd_current_size: None,
        vhd_unique_id_hex: None,
        vhdx_creator: None,
        limitations: limitations.to_vec(),
    };
    if let Some(vhd) = &format.vhd {
        record.vhd_footer_offset = Some(vhd.footer_offset);
        record.vhd_disk_type = Some(vhd.disk_type);
        record.vhd_disk_type_label = Some(vhd.disk_type_label().to_owned());
        record.vhd_current_size = Some(vhd.current_size);
        record.vhd_unique_id_hex = Some(vhd.unique_id_hex.clone());
    }
    if let Some(vhdx) = &format.vhdx {
        record.vhdx_creator = Some(vhdx.creator.clone());
    }
    run.record(&record).from(file).note(file.name()).emit()
}

fn bitlocker_vhd(run: &Run) -> Result<()> {
    let mut files = 0usize;
    let mut hits = 0usize;
    let mut guids = 0usize;
    let mut skipped = 0usize;

    for file in run.inputs() {
        run.check_cancelled()?;
        files += 1;
        let file_size = file.size();
        let header_length = file_size.min(520) as usize;
        let header = match file.read_at(0, header_length) {
            Ok(header) => header,
            Err(error) => {
                skipped += 1;
                run.warn_file(file, &error.code, error.message)?;
                continue;
            }
        };
        if header.len() < header_length {
            skipped += 1;
            run.warn_file(
                file,
                "SHORT_READ",
                format!(
                    "{} 文件头只读到 {} / {header_length} 字节，拒绝在不完整数据上判断格式",
                    file.name(),
                    header.len()
                ),
            )?;
            continue;
        }
        let footer = if file_size >= parser::VHD_FOOTER_SIZE {
            let offset = file_size - parser::VHD_FOOTER_SIZE;
            match file.read_at(offset, parser::VHD_FOOTER_SIZE as usize) {
                Ok(footer) if footer.len() == parser::VHD_FOOTER_SIZE as usize => Some(footer),
                Ok(footer) => {
                    skipped += 1;
                    run.warn_file(
                        file,
                        "SHORT_READ",
                        format!(
                            "{} VHD footer 只读到 {} / {} 字节，拒绝在不完整数据上判断格式",
                            file.name(),
                            footer.len(),
                            parser::VHD_FOOTER_SIZE
                        ),
                    )?;
                    continue;
                }
                Err(error) => {
                    skipped += 1;
                    run.warn_file(file, &error.code, error.message)?;
                    continue;
                }
            }
        } else {
            None
        };

        let format = parser::detect_format(file_size, &header, footer.as_deref());
        let reader = Reader(file);
        let scan = match parser::scan_for_signatures(
            &reader,
            parser::SCAN_CHUNK_BYTES,
            parser::MAX_SIGNATURE_HITS,
            || run.check_cancelled().map_err(|error| error.to_string()),
        ) {
            Ok(scan) => scan,
            Err(message) => {
                if run.is_cancelled() {
                    return Err(Error::cancelled());
                }
                skipped += 1;
                run.warn_file(
                    file,
                    "BITLOCKER_SCAN_FAILED",
                    format!("{}: {message}", file.name()),
                )?;
                continue;
            }
        };
        let volumes: Vec<parser::FveVolume> = scan
            .offsets
            .iter()
            .map(|offset| parser::parse_fve_volume(&reader, *offset))
            .collect();
        let recovery_guids = collect_recovery_guids(&volumes);
        let limitations = collect_limitations(file_size, &format, &scan, &volumes, &recovery_guids);

        emit_image(run, file, &format, &scan, &recovery_guids, &limitations)?;

        for volume in &volumes {
            run.check_cancelled()?;
            let mut hit = BitlockerHit {
                signature_offset: volume.signature_offset,
                volume_header_offset: volume.volume_header_offset,
                boot_entry: volume.boot_entry.map(parser::boot_entry_hex),
                parse_status: volume.status.as_str().to_owned(),
                parse_basis: volume.parse_basis.as_str().to_owned(),
                metadata_block_offset: None,
                metadata_version: None,
                metadata_size: None,
                metadata_volume_id: None,
                encryption_method: None,
                encryption_method_label: None,
                vmk_count: 0,
                recovery_key_guid_count: 0,
                recovery_key_guids: Vec::new(),
                parse_error: volume.error.clone(),
                limitations: volume.limitations.clone(),
            };
            if let Some(metadata) = &volume.metadata {
                hit.metadata_block_offset = Some(metadata.block_offset);
                hit.metadata_version = Some(u64::from(metadata.block_version));
                hit.metadata_size = Some(u64::from(metadata.metadata_size));
                hit.metadata_volume_id = metadata.volume_id.clone();
                hit.encryption_method = Some(u64::from(metadata.encryption_method));
                hit.encryption_method_label = Some(metadata.encryption_method_label());
                hit.vmk_count = metadata.vmk_entries.len();
                hit.recovery_key_guid_count = metadata.recovery_key_guids.len();
                hit.recovery_key_guids = metadata.recovery_key_guids.clone();
            }
            run.record(&hit)
                .from(file)
                .at(volume.signature_offset, parser::FVE_SIGNATURE.len() as u64)
                .note(format!("@0x{:X}", volume.signature_offset))
                .emit()?;
            hits += 1;

            if let Some(metadata) = &volume.metadata {
                for (index, entry) in metadata.vmk_entries.iter().enumerate() {
                    run.record(&BitlockerVmk {
                        vmk_guid: entry.guid.clone(),
                        protection_type: u32::from(entry.protection_type),
                        protection_label: parser::protection_type_label(entry.protection_type),
                        is_recovery_key: entry.is_recovery_key,
                        signature_offset: volume.signature_offset,
                        metadata_block_offset: metadata.block_offset,
                        index: index + 1,
                    })
                    .from(file)
                    .note(format!("@0x{:X}#vmk{}", volume.signature_offset, index + 1))
                    .emit()?;
                }
            }
        }
        if scan.truncated {
            run.warn_file(
                file,
                "SCAN_TRUNCATED",
                format!(
                    "{}: 文件 {} 字节，只扫描前 {} 字节；未扫描区域没有结论",
                    file.name(),
                    file_size,
                    scan.scan_limit
                ),
            )?;
        }
        if scan.hit_limit_reached {
            run.warn_file(
                file,
                "SIGNATURE_HIT_LIMIT",
                format!(
                    "{}: FVE 签名命中达到 {} 个上限，扫描提前停止",
                    file.name(),
                    parser::MAX_SIGNATURE_HITS
                ),
            )?;
        }
        guids += recovery_guids.len();
    }

    if run.inputs().is_empty() {
        run.warn(
            "INPUT_NOT_FOUND",
            "未选择磁盘镜像文件；请选择 VHD/VHDX（或任意镜像）后运行",
        )?;
    }
    run.set_summary(format!(
        "分析 {files} 个镜像，输出 {hits} 个 FVE 签名命中、{guids} 个恢复密钥 GUID，跳过 {skipped} 个。只读识别，不解密、不挂载。"
    ));
    Ok(())
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.bitlocker-vhd")
        .record::<BitlockerImage>()
        .record::<BitlockerHit>()
        .record::<BitlockerVmk>()
        .analyzer("bitlocker_vhd", bitlocker_vhd)
}

export_plugin!(plugin);
