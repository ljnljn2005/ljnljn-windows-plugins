//! LovelyCarve 单文件分析器：识别 BitLocker 加密的 VHD/VHDX 磁盘镜像。
//!
//! 离线、只读、最小能力：
//!
//! 1. **格式**：VHD 读取文件最后 512 字节的 `conectix` footer；VHDX 读取文件头
//!    `vhdxfile`。两者都不解析分区表、不展开动态块、不验证校验和。
//! 2. **签名**：在文件前 [`parser::MAX_SCAN_BYTES`] 字节内分块扫描 BitLocker
//!    引导签名 `2D 46 56 45 2D 46 53 2D`（`-FVE-FS-`），逐条输出文件绝对偏移。
//! 3. **FVE 元数据**：对签名前 3 字节为 `EB ?? 90` 的候选，尝试 Windows 7+
//!    卷头的 176/184/192 字节处三个元数据块偏移，读取元数据块头、元数据头与
//!    VMK 条目。恢复密钥 GUID 只取 protection type = 0x0800 的 VMK 的 16 字节
//!    标识符；无法解析时逐条写入 `limitations`，不猜测。
//!
//! 不做：解密、挂载、执行镜像内容、提取 48 位恢复密钥、分区表/文件系统解析、
//! VHD 动态块与差异盘链、Vista 卷头布局、BitLocker To Go FAT 布局、外部恢复
//! 密钥文件匹配、真实引擎/真实检材验证声明。
//!
//! ## 输出字段（汇总 artifact `bitlocker.vhd.file`）
//!
//! | 需求 | attribute | 说明 |
//! | --- | --- | --- |
//! | 来源文件句柄 | `source.file_id` | 宿主下发的逻辑文件句柄 |
//! | 来源显示名 | `source.path` / `bitlocker.file_name` | SDK 只给显示名，不给宿主真实路径 |
//! | 文件大小 | `bitlocker.file_size` | 字节 |
//! | 格式 | `bitlocker.format` / `bitlocker.format_label` | `vhd` / `vhdx` / `unknown` |
//! | 格式签名偏移 | `bitlocker.format_signature_offset` | VHDX 为 0；VHD 为文件尾 footer 起点 |
//! | 签名偏移 | `bitlocker.signature_offsets` / 每个 hit 的 `bitlocker.signature_offset` | `-FVE-FS-` 的文件绝对偏移 |
//! | GUID | `bitlocker.recovery_key_guids` / `bitlocker.recovery_key_guid` | 仅 0x0800 VMK 标识符 |
//! | 是否加密 | `bitlocker.encrypted` | 仅表示扫描范围内命中签名，不等于解密验证 |
//! | 未覆盖项 | `bitlocker.limitations` + finding | 静态与动态限制 |

mod parser;

use lovelycarve_plugin::{
    AnalysisResult, Artifact, Attributes, Error, File, FileAnalyzer, Finding, LogLevel, Plugin,
    Result, ResultColumn, ResultNode, Severity, Value,
};

/// 插件身份：必须与 plugin.toml 的 `id` 一致。
pub const PLUGIN_ID: &str = "org.ljnljn.bitlocker-vhd";
/// 显示名：必须与 plugin.toml 的 `name` 一致。
pub const PLUGIN_NAME: &str = "BitLocker VHD/VHDX 识别";
/// 必须与 plugin.toml 的 `[[capabilities]].analyzer` 一致。
pub const ANALYZER: &str = "ljnljn.bitlocker-vhd.file";

/// 文件级汇总 artifact 类型。
pub const FILE_TYPE: &str = "bitlocker.vhd.file";
/// 单个 `-FVE-FS-` 命中 artifact 类型。
pub const HIT_TYPE: &str = "bitlocker.vhd.hit";
/// 单个 VMK 条目 artifact 类型。
pub const VMK_TYPE: &str = "bitlocker.vhd.vmk";

/// 宿主对单次分析结果的上限（LPP v1：最多 10000 项）。
const MAX_RESULT_ITEMS: usize = 10_000;

/// 静态未覆盖项；与动态限制一起写入 `bitlocker.limitations`。
const STATIC_LIMITATIONS: [&str; 6] = [
    "只读识别：不解密、不挂载、不执行 VHD/VHDX 内容，不提取 48 位恢复密钥数字密码，不联网。",
    "格式识别只检查 VHDX 文件头 vhdxfile 与 VHD 文件尾 512 字节的 conectix 签名；不验证 VHD/VHDX 校验和，不解析动态块、差异盘链或分区表。",
    "BitLocker 签名按文件绝对偏移扫描并输出；不解析 VHD/VHDX 分区表，因此不判断签名属于哪个分区或卷。",
    "FVE 元数据优先按 Windows 7+ 启动卷头布局（元数据块偏移 176/184/192，要求命中前 3 字节为 EB ?? 90）解析；前缀不符时仅尝试把命中处当作独立元数据块直接解析。Vista 卷头与 BitLocker To Go FAT（MSWIN4.1）布局未解析。",
    "恢复密钥 GUID 只从 FVE VMK 条目中 protection type = 0x0800 的 16 字节标识符读取；不从文件名、txt、注册表或外部恢复密钥文件推断/匹配。",
    "签名存在只说明字节模式命中，可能是真实 BitLocker 卷头、元数据副本、残留或伪造；未命中也不排除签名位于扫描上限之外。",
];

/// 把 SDK 的只读 `File` 适配成 parser 的随机读取接口。
struct FileReader<'a>(&'a File);

impl parser::ImageReader for FileReader<'_> {
    fn size(&self) -> u64 {
        self.0.size()
    }

    fn read_at(&self, offset: u64, length: usize) -> std::result::Result<Vec<u8>, String> {
        self.0
            .read(offset, length)
            .map_err(|error| error.to_string())
    }
}

/// 可选的来源显示名：宿主只给显示名，不给真实路径。
fn source_base(file: &File) -> String {
    let name = file.name().trim();
    if name.is_empty() {
        format!("file:{}", file.id())
    } else {
        name.replace('\\', "/")
    }
}

fn value_string_array(items: &[String]) -> Value {
    Value::Array(
        items
            .iter()
            .map(|item| Value::from(item.as_str()))
            .collect(),
    )
}

fn value_u64_array(items: &[u64]) -> Value {
    Value::Array(items.iter().copied().map(Value::from).collect())
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

fn columns(spec: &[(&str, &str)]) -> Vec<ResultColumn> {
    spec.iter()
        .map(|(key, label)| ResultColumn {
            key: (*key).to_string(),
            label: (*label).to_string(),
        })
        .collect()
}

fn result_nodes(volumes: &[parser::FveVolume], has_vmks: bool) -> Vec<ResultNode> {
    let mut nodes = vec![ResultNode {
        node_type: FILE_TYPE.to_string(),
        name: "BitLocker 镜像识别".to_string(),
        columns: columns(&[
            ("source.path", "来源文件"),
            ("bitlocker.format", "格式"),
            ("bitlocker.file_size", "文件大小"),
            ("bitlocker.encrypted", "是否命中签名"),
            ("bitlocker.signature_count", "签名数"),
            ("bitlocker.recovery_key_guid_count", "恢复密钥 GUID 数"),
            ("bitlocker.scan_bytes", "已扫描字节"),
            ("bitlocker.scan_truncated", "扫描被上限截断"),
        ]),
    }];

    if !volumes.is_empty() {
        nodes.push(ResultNode {
            node_type: HIT_TYPE.to_string(),
            name: "FVE 签名命中".to_string(),
            columns: columns(&[
                ("bitlocker.signature_offset", "签名偏移"),
                ("bitlocker.volume_header_offset", "卷头偏移"),
                ("bitlocker.parse_status", "解析状态"),
                ("bitlocker.parse_basis", "解析依据"),
                ("bitlocker.metadata_block_offset", "元数据块偏移"),
                ("bitlocker.recovery_key_guid_count", "恢复密钥 GUID 数"),
                ("bitlocker.source_ref", "来源定位"),
            ]),
        });
    }
    if has_vmks {
        nodes.push(ResultNode {
            node_type: VMK_TYPE.to_string(),
            name: "FVE VMK 条目".to_string(),
            columns: columns(&[
                ("bitlocker.source_ref", "来源定位"),
                ("bitlocker.vmk_guid", "VMK GUID"),
                ("bitlocker.protection_type", "保护类型"),
                ("bitlocker.protection_label", "保护类型标签"),
                ("bitlocker.is_recovery_key", "是否恢复密钥"),
            ]),
        });
    }
    nodes
}

fn build_findings(
    base: &str,
    format: &parser::FormatInfo,
    scan: &parser::ScanOutcome,
    volumes: &[parser::FveVolume],
    recovery_guids: &[String],
    limitations: &[String],
) -> Vec<Finding> {
    let mut findings = vec![Finding {
        severity: Severity::Info,
        title: "解析范围与未覆盖项".to_string(),
        description: format!(
            "只读识别，不解密、不挂载、不执行镜像内容。格式只按 VHDX 文件头与 VHD 文件尾签名判断；FVE 签名按绝对偏移扫描；元数据仅尝试 Windows 7+ 卷头布局；恢复密钥 GUID 仅取 protection type = 0x0800 的 VMK；未命中不代表未加密。共 {} 条限制，逐条见 attributes。",
            limitations.len()
        ),
        attributes: [
            ("source.path", Value::from(base)),
            ("bitlocker.format", Value::from(format.format.as_str())),
            ("bitlocker.limitations", value_string_array(limitations)),
        ]
        .into_iter()
        .collect(),
    }];

    if format.format == parser::Format::Unknown {
        findings.push(Finding {
            severity: Severity::Low,
            title: "未识别为 VHD/VHDX".to_string(),
            description:
                "文件头不是 vhdxfile，文件尾 512 字节也不是 conectix；仍扫描了 FVE 签名，但格式结论为 unknown。"
                    .to_string(),
            attributes: [("source.path", Value::from(base))].into_iter().collect(),
        });
    }
    if scan.truncated || scan.hit_limit_reached {
        findings.push(Finding {
            severity: Severity::Low,
            title: "扫描范围被上限截断".to_string(),
            description: format!(
                "已扫描 {} 字节，扫描上限 {} 字节；命中上限 {} 个；截断部分没有结论。",
                scan.bytes_scanned,
                parser::MAX_SCAN_BYTES,
                parser::MAX_SIGNATURE_HITS
            ),
            attributes: [("source.path", Value::from(base))].into_iter().collect(),
        });
    }
    if !scan.offsets.is_empty() && recovery_guids.is_empty() {
        let summary = volumes
            .iter()
            .map(|volume| {
                format!(
                    "@0x{:X}={}",
                    volume.signature_offset,
                    volume.status.as_str()
                )
            })
            .collect::<Vec<_>>()
            .join("、");
        findings.push(Finding {
            severity: Severity::Low,
            title: "发现 BitLocker 签名但恢复密钥 GUID 未解析".to_string(),
            description: format!(
                "命中 {} 处 -FVE-FS-（{summary}）；未找到可用的保护类型 0x0800 VMK 时明确留空，不猜测 GUID。",
                scan.offsets.len()
            ),
            attributes: [("source.path", Value::from(base))].into_iter().collect(),
        });
    }
    if scan.offsets.is_empty() {
        findings.push(Finding {
            severity: Severity::Info,
            title: "已扫描范围内未发现 BitLocker 引导签名".to_string(),
            description: format!(
                "扫描 {} 字节，未命中 -FVE-FS-；该结论只覆盖已扫描范围。",
                scan.bytes_scanned
            ),
            attributes: [("source.path", Value::from(base))].into_iter().collect(),
        });
    }
    if !recovery_guids.is_empty() {
        findings.push(Finding {
            severity: Severity::Info,
            title: "已解析恢复密钥 GUID".to_string(),
            description: format!(
                "从 FVE VMK 条目解析到 {} 个恢复密钥 GUID：{}。GUID 是恢复密钥标识符，不是 48 位恢复密钥本身。",
                recovery_guids.len(),
                recovery_guids.join("、")
            ),
            attributes: [
                ("source.path", Value::from(base)),
                (
                    "bitlocker.recovery_key_guids",
                    value_string_array(recovery_guids),
                ),
            ]
            .into_iter()
            .collect(),
        });
    }

    findings
}

/// 把解析结果转成 LPP 结果对象；纯函数，便于用合成字节测试。
#[allow(clippy::too_many_arguments)]
pub fn build_result(
    base: &str,
    file_id: &str,
    file_name: &str,
    mime: &str,
    file_size: u64,
    format: &parser::FormatInfo,
    scan: &parser::ScanOutcome,
    volumes: &[parser::FveVolume],
) -> AnalysisResult {
    let recovery_guids = collect_recovery_guids(volumes);
    let limitations = collect_limitations(file_size, format, scan, volumes, &recovery_guids);
    let encrypted = !scan.offsets.is_empty();

    let mut summary_attributes: Attributes = [
        ("source.path", Value::from(base)),
        ("source.file_id", Value::from(file_id)),
        ("source.mime", Value::from(mime)),
        ("bitlocker.source", Value::from(base)),
        ("bitlocker.file_name", Value::from(file_name)),
        ("bitlocker.file_size", Value::from(file_size)),
        ("bitlocker.format", Value::from(format.format.as_str())),
        ("bitlocker.format_label", Value::from(format.format.label())),
        ("bitlocker.encrypted", Value::from(encrypted)),
        (
            "bitlocker.encryption_evidence",
            Value::from(if encrypted {
                "fve_signature"
            } else {
                "none_in_scanned_range"
            }),
        ),
        (
            "bitlocker.signature_count",
            Value::from(scan.offsets.len() as u64),
        ),
        (
            "bitlocker.recovery_key_guid_count",
            Value::from(recovery_guids.len() as u64),
        ),
        ("bitlocker.scan_bytes", Value::from(scan.bytes_scanned)),
        ("bitlocker.scan_limit", Value::from(scan.scan_limit)),
        ("bitlocker.scan_truncated", Value::from(scan.truncated)),
        (
            "bitlocker.hit_limit_reached",
            Value::from(scan.hit_limit_reached),
        ),
    ]
    .into_iter()
    .collect();

    summary_attributes.insert_optional("bitlocker.format_signature", format.signature());
    summary_attributes
        .insert_optional("bitlocker.format_signature_offset", format.signature_offset);
    summary_attributes.insert(
        "bitlocker.signature_offsets",
        value_u64_array(&scan.offsets),
    );
    summary_attributes.insert_optional(
        "bitlocker.first_signature_offset",
        scan.offsets.first().copied(),
    );
    summary_attributes.insert_optional(
        "bitlocker.recovery_key_guid",
        recovery_guids.first().cloned(),
    );
    summary_attributes.insert(
        "bitlocker.recovery_key_guids",
        value_string_array(&recovery_guids),
    );
    summary_attributes.insert("bitlocker.limitations", value_string_array(&limitations));

    if let Some(vhd) = &format.vhd {
        summary_attributes.insert("vhd.footer_offset", Value::from(vhd.footer_offset));
        summary_attributes.insert("vhd.disk_type", Value::from(u64::from(vhd.disk_type)));
        summary_attributes.insert("vhd.disk_type_label", Value::from(vhd.disk_type_label()));
        summary_attributes.insert("vhd.current_size", Value::from(vhd.current_size));
        summary_attributes.insert("vhd.unique_id_hex", Value::from(vhd.unique_id_hex.as_str()));
    }
    if let Some(vhdx) = &format.vhdx {
        summary_attributes.insert("vhdx.creator", Value::from(vhdx.creator.as_str()));
    }

    let mut artifacts = Vec::with_capacity(1 + volumes.len() * 2);
    artifacts.push(Artifact {
        artifact_type: FILE_TYPE.to_string(),
        title: format!("{base} BitLocker VHD/VHDX 识别"),
        value: Some(Value::from(base)),
        attributes: summary_attributes,
    });

    for volume in volumes {
        let source_ref = format!("{base}@0x{:X}", volume.signature_offset);
        let mut attributes: Attributes = [
            ("source.path", Value::from(base)),
            ("source.file_id", Value::from(file_id)),
            ("bitlocker.source_ref", Value::from(source_ref.as_str())),
            (
                "bitlocker.signature_offset",
                Value::from(volume.signature_offset),
            ),
            (
                "bitlocker.parse_status",
                Value::from(volume.status.as_str()),
            ),
            (
                "bitlocker.parse_basis",
                Value::from(volume.parse_basis.as_str()),
            ),
        ]
        .into_iter()
        .collect();
        attributes.insert_optional(
            "bitlocker.volume_header_offset",
            volume.volume_header_offset,
        );
        attributes.insert_optional(
            "bitlocker.boot_entry",
            volume.boot_entry.map(parser::boot_entry_hex),
        );
        attributes.insert_optional("bitlocker.parse_error", volume.error.as_deref());

        if let Some(metadata) = &volume.metadata {
            attributes.insert(
                "bitlocker.metadata_block_offset",
                Value::from(metadata.block_offset),
            );
            attributes.insert(
                "bitlocker.metadata_version",
                Value::from(u64::from(metadata.block_version)),
            );
            attributes.insert(
                "bitlocker.metadata_size",
                Value::from(u64::from(metadata.metadata_size)),
            );
            attributes.insert_optional(
                "bitlocker.metadata_volume_id",
                metadata.volume_id.as_deref(),
            );
            attributes.insert(
                "bitlocker.encryption_method",
                Value::from(u64::from(metadata.encryption_method)),
            );
            attributes.insert(
                "bitlocker.encryption_method_label",
                Value::from(metadata.encryption_method_label()),
            );
            attributes.insert(
                "bitlocker.vmk_count",
                Value::from(metadata.vmk_entries.len() as u64),
            );
            attributes.insert(
                "bitlocker.recovery_key_guid_count",
                Value::from(metadata.recovery_key_guids.len() as u64),
            );
            attributes.insert(
                "bitlocker.recovery_key_guids",
                value_string_array(&metadata.recovery_key_guids),
            );
        } else {
            for key in [
                "bitlocker.metadata_block_offset",
                "bitlocker.metadata_version",
                "bitlocker.metadata_size",
                "bitlocker.metadata_volume_id",
                "bitlocker.encryption_method",
                "bitlocker.encryption_method_label",
            ] {
                attributes.insert(key, Value::Nil);
            }
            attributes.insert("bitlocker.vmk_count", Value::from(0_u64));
            attributes.insert("bitlocker.recovery_key_guid_count", Value::from(0_u64));
            attributes.insert("bitlocker.recovery_key_guids", Value::Array(Vec::new()));
        }
        attributes.insert(
            "bitlocker.limitations",
            value_string_array(&volume.limitations),
        );

        artifacts.push(Artifact {
            artifact_type: HIT_TYPE.to_string(),
            title: format!("FVE 签名 @0x{:X}", volume.signature_offset),
            value: Some(Value::from(volume.signature_offset)),
            attributes,
        });

        if let Some(metadata) = &volume.metadata {
            for (index, entry) in metadata.vmk_entries.iter().enumerate() {
                let vmk_ref = format!("{source_ref}#vmk{}", index + 1);
                let vmk_attributes: Attributes = [
                    ("source.path", Value::from(base)),
                    ("source.file_id", Value::from(file_id)),
                    ("bitlocker.source_ref", Value::from(vmk_ref.as_str())),
                    (
                        "bitlocker.signature_offset",
                        Value::from(volume.signature_offset),
                    ),
                    (
                        "bitlocker.metadata_block_offset",
                        Value::from(metadata.block_offset),
                    ),
                    ("bitlocker.vmk_guid", Value::from(entry.guid.as_str())),
                    (
                        "bitlocker.protection_type",
                        Value::from(u64::from(entry.protection_type)),
                    ),
                    (
                        "bitlocker.protection_label",
                        Value::from(parser::protection_type_label(entry.protection_type)),
                    ),
                    (
                        "bitlocker.is_recovery_key",
                        Value::from(entry.is_recovery_key),
                    ),
                ]
                .into_iter()
                .collect();
                artifacts.push(Artifact {
                    artifact_type: VMK_TYPE.to_string(),
                    title: format!(
                        "VMK {} · {}",
                        entry.guid,
                        parser::protection_type_label(entry.protection_type)
                    ),
                    value: Some(Value::from(entry.guid.as_str())),
                    attributes: vmk_attributes,
                });
            }
        }
    }

    if artifacts.len() > MAX_RESULT_ITEMS {
        artifacts.truncate(MAX_RESULT_ITEMS);
    }

    let has_vmks = volumes.iter().any(|volume| {
        volume
            .metadata
            .as_ref()
            .is_some_and(|metadata| !metadata.vmk_entries.is_empty())
    });

    let summary = format!(
        "{}：格式 {}，{} 字节，扫描 {}/{} 字节，命中 {} 个 -FVE-FS- 签名；恢复密钥 GUID：{}。仅识别，不解密。",
        base,
        format.format.label(),
        file_size,
        scan.bytes_scanned,
        scan.scan_limit,
        scan.offsets.len(),
        if recovery_guids.is_empty() {
            "未解析".to_string()
        } else {
            recovery_guids.join("、")
        }
    );

    AnalysisResult {
        summary: Some(summary),
        nodes: result_nodes(volumes, has_vmks),
        artifacts,
        timeline: Vec::new(),
        findings: build_findings(base, format, scan, volumes, &recovery_guids, &limitations),
    }
}

/// `file_analyzer`：`analyzer` 返回值必须与 plugin.toml 的 capabilities 一致。
pub struct BitlockerVhdAnalyzer;

impl FileAnalyzer for BitlockerVhdAnalyzer {
    fn analyzer(&self) -> &str {
        ANALYZER
    }

    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        file.context().check_cancelled()?;
        let base = source_base(file);
        let file_size = file.size();

        let header_length = file_size.min(520) as usize;
        let header = file.read(0, header_length)?;
        if header.len() < header_length {
            return Err(Error::new(
                "SHORT_READ",
                format!(
                    "{base} 文件头只读到 {} / {} 字节，拒绝在不完整数据上判断格式",
                    header.len(),
                    header_length
                ),
            ));
        }

        let footer = if file_size >= parser::VHD_FOOTER_SIZE {
            let footer_offset = file_size - parser::VHD_FOOTER_SIZE;
            let footer = file.read(footer_offset, parser::VHD_FOOTER_SIZE as usize)?;
            if footer.len() < parser::VHD_FOOTER_SIZE as usize {
                return Err(Error::new(
                    "SHORT_READ",
                    format!(
                        "{base} VHD footer 只读到 {} / {} 字节，拒绝在不完整数据上判断格式",
                        footer.len(),
                        parser::VHD_FOOTER_SIZE
                    ),
                ));
            }
            Some(footer)
        } else {
            None
        };

        let format = parser::detect_format(file_size, &header, footer.as_deref());
        let reader = FileReader(file);
        let scan = parser::scan_for_signatures(
            &reader,
            parser::SCAN_CHUNK_BYTES,
            parser::MAX_SIGNATURE_HITS,
            || {
                file.context()
                    .check_cancelled()
                    .map_err(|error| error.to_string())
            },
        )
        .map_err(|message| {
            if file.context().is_cancelled() {
                Error::cancelled()
            } else {
                Error::new("PLUGIN_ERROR", message)
            }
        })?;

        let mut volumes = Vec::with_capacity(scan.offsets.len());
        for offset in &scan.offsets {
            file.context().check_cancelled()?;
            volumes.push(parser::parse_fve_volume(&reader, *offset));
        }
        file.context().check_cancelled()?;

        let result = build_result(
            &base,
            file.id(),
            file.name(),
            file.mime(),
            file_size,
            &format,
            &scan,
            &volumes,
        );
        file.context().log(
            LogLevel::Info,
            &format!(
                "BitLocker VHD/VHDX 识别完成：{}",
                result.summary.clone().unwrap_or_default()
            ),
        );
        Ok(result)
    }
}

fn plugin() -> Plugin {
    Plugin::new(PLUGIN_ID, PLUGIN_NAME, env!("CARGO_PKG_VERSION"))
        .file_analyzer(BitlockerVhdAnalyzer)
}

lovelycarve_plugin::export_plugin!(plugin);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::fixtures::{self, TestVmk};

    struct SliceReader<'a>(&'a [u8]);

    impl parser::ImageReader for SliceReader<'_> {
        fn size(&self) -> u64 {
            self.0.len() as u64
        }

        fn read_at(&self, offset: u64, length: usize) -> std::result::Result<Vec<u8>, String> {
            if offset > self.0.len() as u64 {
                return Ok(Vec::new());
            }
            let start = offset as usize;
            let end = start.saturating_add(length).min(self.0.len());
            Ok(self.0[start..end].to_vec())
        }
    }

    fn test_guid(seed: u8) -> [u8; 16] {
        let mut guid = [seed; 16];
        guid[0] = 0x10;
        guid[1] = 0x20;
        guid[2] = 0x30;
        guid[3] = 0x40;
        guid[4] = 0x50;
        guid[5] = 0x60;
        guid[6] = 0x70;
        guid[7] = 0x80;
        guid
    }

    fn build_vhd_image(recovery_guid: Option<[u8; 16]>) -> Vec<u8> {
        let vmks = match recovery_guid {
            Some(guid) => vec![
                fixtures::tpm_vmk(test_guid(0x01)),
                fixtures::recovery_vmk(guid),
            ],
            None => vec![fixtures::tpm_vmk(test_guid(0x02))],
        };
        let volume = fixtures::fve_volume(&vmks);
        let mut image = vec![0_u8; fixtures::TEST_VOLUME_OFFSET as usize];
        image.extend_from_slice(&volume);
        image.resize(8192, 0);
        let footer = fixtures::vhd_footer(3, 1024 * 1024);
        image[8192 - 512..].copy_from_slice(&footer);
        image
    }

    fn analyze_slice(
        image: &[u8],
    ) -> (
        parser::FormatInfo,
        parser::ScanOutcome,
        Vec<parser::FveVolume>,
        AnalysisResult,
    ) {
        let header_length = image.len().min(520);
        let header = &image[..header_length];
        let footer = if image.len() >= 512 {
            Some(&image[image.len() - 512..])
        } else {
            None
        };
        let format = parser::detect_format(image.len() as u64, header, footer);
        let reader = SliceReader(image);
        let scan = parser::scan_for_signatures(&reader, 4096, 16, || Ok(()))
            .expect("synthetic scan succeeds");
        let volumes: Vec<_> = scan
            .offsets
            .iter()
            .map(|offset| parser::parse_fve_volume(&reader, *offset))
            .collect();
        let result = build_result(
            "synthetic.vhd",
            "file-1",
            "synthetic.vhd",
            "application/octet-stream",
            image.len() as u64,
            &format,
            &scan,
            &volumes,
        );
        (format, scan, volumes, result)
    }

    fn attribute<'a>(artifact: &'a Artifact, key: &str) -> &'a Value {
        artifact
            .attributes
            .get(key)
            .unwrap_or_else(|| panic!("missing attribute {key}"))
    }

    #[test]
    fn identity_matches_manifest_expectations() {
        assert_eq!(PLUGIN_ID, "org.ljnljn.bitlocker-vhd");
        assert_eq!(ANALYZER, "ljnljn.bitlocker-vhd.file");
        assert_eq!(FILE_TYPE, "bitlocker.vhd.file");
        assert_eq!(HIT_TYPE, "bitlocker.vhd.hit");
        assert_eq!(VMK_TYPE, "bitlocker.vhd.vmk");
        assert_eq!(env!("CARGO_PKG_NAME"), "ljnljn-bitlocker-vhd-8f3c2a10");
        let _ = plugin();
        assert_eq!(BitlockerVhdAnalyzer.analyzer(), ANALYZER);
    }

    #[test]
    fn result_reports_required_fields_for_vhd_with_recovery_guid() {
        let guid = test_guid(0xAA);
        let guid_text = parser::format_guid(&guid).expect("guid");
        let image = build_vhd_image(Some(guid));
        let (format, scan, volumes, result) = analyze_slice(&image);

        assert_eq!(format.format, parser::Format::Vhd);
        assert_eq!(scan.offsets.len(), 2, "卷头签名 + 元数据块签名");
        assert_eq!(
            volumes[0].status,
            parser::ParseStatus::Parsed,
            "第一个命中是引导卷头"
        );
        assert_eq!(
            volumes[0].metadata.as_ref().unwrap().block_offset,
            fixtures::TEST_BLOCK_OFFSET
        );

        let summary = &result.artifacts[0];
        assert_eq!(summary.artifact_type, FILE_TYPE);
        assert_eq!(
            attribute(summary, "source.path").as_str(),
            Some("synthetic.vhd")
        );
        assert_eq!(
            attribute(summary, "source.file_id").as_str(),
            Some("file-1")
        );
        assert_eq!(
            attribute(summary, "bitlocker.file_size").as_u64(),
            Some(image.len() as u64)
        );
        assert_eq!(attribute(summary, "bitlocker.format").as_str(), Some("vhd"));
        assert_eq!(
            attribute(summary, "bitlocker.format_signature").as_str(),
            Some("conectix")
        );
        assert_eq!(
            attribute(summary, "bitlocker.format_signature_offset").as_u64(),
            Some(8192 - 512)
        );
        assert_eq!(
            attribute(summary, "bitlocker.encrypted").as_bool(),
            Some(true)
        );
        let offsets = attribute(summary, "bitlocker.signature_offsets")
            .as_array()
            .expect("offsets array");
        assert!(offsets.iter().any(|value| value.as_u64() == Some(1027)));
        assert_eq!(
            attribute(summary, "bitlocker.first_signature_offset").as_u64(),
            Some(1027)
        );
        let guids = attribute(summary, "bitlocker.recovery_key_guids")
            .as_array()
            .expect("guids array");
        assert_eq!(guids.len(), 1);
        assert_eq!(guids[0].as_str(), Some(guid_text.as_str()));
        assert_eq!(
            attribute(summary, "bitlocker.recovery_key_guid").as_str(),
            Some(guid_text.as_str())
        );
        assert!(!attribute(summary, "bitlocker.limitations")
            .as_array()
            .expect("limitations")
            .is_empty());

        assert_eq!(
            attribute(summary, "vhd.disk_type_label").as_str(),
            Some("动态磁盘")
        );
        assert_eq!(
            attribute(summary, "vhd.unique_id_hex").as_str(),
            Some("11".repeat(16).as_str())
        );

        assert!(result
            .artifacts
            .iter()
            .any(|artifact| artifact.artifact_type == HIT_TYPE));
        assert!(result
            .artifacts
            .iter()
            .any(|artifact| artifact.artifact_type == VMK_TYPE
                && attribute(artifact, "bitlocker.vmk_guid").as_str() == Some(guid_text.as_str())
                && attribute(artifact, "bitlocker.is_recovery_key").as_bool() == Some(true)));
    }

    #[test]
    fn result_explicitly_reports_missing_recovery_guid() {
        let image = build_vhd_image(None);
        let (_, _, volumes, result) = analyze_slice(&image);
        assert_eq!(volumes[0].status, parser::ParseStatus::Parsed);
        let summary = &result.artifacts[0];
        assert_eq!(
            attribute(summary, "bitlocker.encrypted").as_bool(),
            Some(true)
        );
        assert!(attribute(summary, "bitlocker.recovery_key_guids")
            .as_array()
            .expect("guids")
            .is_empty());
        let limitations = attribute(summary, "bitlocker.limitations")
            .as_array()
            .expect("limitations");
        assert!(limitations
            .iter()
            .any(|value| value.as_str().is_some_and(|text| text.contains("0x0800"))));
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.title.contains("恢复密钥 GUID 未解析")));
    }

    #[test]
    fn vhdx_without_fve_is_reported_as_unencrypted_in_scan_range() {
        let mut image = fixtures::vhdx_identifier("synthetic-vhdx");
        image.resize(128 * 1024, 0);
        let header = &image[..520];
        let format = parser::detect_format(image.len() as u64, header, None);
        let reader = SliceReader(&image);
        let scan = parser::scan_for_signatures(&reader, 4096, 16, || Ok(())).expect("scan");
        let result = build_result(
            "synthetic.vhdx",
            "file-2",
            "synthetic.vhdx",
            "application/octet-stream",
            image.len() as u64,
            &format,
            &scan,
            &[],
        );
        let summary = &result.artifacts[0];
        assert_eq!(
            attribute(summary, "bitlocker.format").as_str(),
            Some("vhdx")
        );
        assert_eq!(
            attribute(summary, "bitlocker.format_signature_offset").as_u64(),
            Some(0)
        );
        assert_eq!(
            attribute(summary, "bitlocker.encrypted").as_bool(),
            Some(false)
        );
        assert_eq!(
            attribute(summary, "bitlocker.encryption_evidence").as_str(),
            Some("none_in_scanned_range")
        );
        assert_eq!(
            attribute(summary, "vhdx.creator").as_str(),
            Some("synthetic-vhdx")
        );
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.title.contains("未发现 BitLocker 引导签名")));
    }

    #[test]
    fn unknown_format_and_short_file_are_reported() {
        let image = b"not a disk image".to_vec();
        let format = parser::detect_format(image.len() as u64, &image, None);
        let reader = SliceReader(&image);
        let scan = parser::scan_for_signatures(&reader, 4096, 16, || Ok(())).expect("scan");
        let result = build_result(
            "synthetic.bin",
            "file-3",
            "synthetic.bin",
            "application/octet-stream",
            image.len() as u64,
            &format,
            &scan,
            &[],
        );
        let summary = &result.artifacts[0];
        assert_eq!(
            attribute(summary, "bitlocker.format").as_str(),
            Some("unknown")
        );
        let limitations = attribute(summary, "bitlocker.limitations")
            .as_array()
            .expect("limitations");
        assert!(limitations.iter().any(|value| value
            .as_str()
            .is_some_and(|text| text.contains("小于 VHD footer"))));
        assert!(result
            .findings
            .iter()
            .any(|finding| finding.title == "未识别为 VHD/VHDX"));
    }

    #[test]
    fn result_nodes_declare_expected_columns() {
        let image = build_vhd_image(Some(test_guid(0xBB)));
        let (_, _, _, result) = analyze_slice(&image);
        let types: Vec<&str> = result
            .nodes
            .iter()
            .map(|node| node.node_type.as_str())
            .collect();
        assert_eq!(types, vec![FILE_TYPE, HIT_TYPE, VMK_TYPE]);
        let file_columns: Vec<&str> = result.nodes[0]
            .columns
            .iter()
            .map(|column| column.key.as_str())
            .collect();
        assert_eq!(
            file_columns,
            vec![
                "source.path",
                "bitlocker.format",
                "bitlocker.file_size",
                "bitlocker.encrypted",
                "bitlocker.signature_count",
                "bitlocker.recovery_key_guid_count",
                "bitlocker.scan_bytes",
                "bitlocker.scan_truncated",
            ]
        );
        assert!(result.nodes[1]
            .columns
            .iter()
            .any(|column| column.key == "bitlocker.signature_offset"));
        assert!(result.nodes[2]
            .columns
            .iter()
            .any(|column| column.key == "bitlocker.vmk_guid"));
    }

    #[test]
    fn metadata_block_hit_is_parsed_as_fallback() {
        let image = build_vhd_image(Some(test_guid(0xCC)));
        let (_, _, volumes, result) = analyze_slice(&image);
        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes[1].status, parser::ParseStatus::Parsed);
        assert_eq!(volumes[1].parse_basis, parser::ParseBasis::MetadataBlock);
        let hit = result
            .artifacts
            .iter()
            .find(|artifact| {
                artifact.artifact_type == HIT_TYPE
                    && attribute(artifact, "bitlocker.signature_offset").as_u64() == Some(5120)
            })
            .expect("metadata block hit artifact");
        assert_eq!(
            attribute(hit, "bitlocker.parse_status").as_str(),
            Some("parsed")
        );
        assert_eq!(
            attribute(hit, "bitlocker.parse_basis").as_str(),
            Some("metadata_block")
        );
    }

    #[test]
    fn metadata_block_is_recovered_when_boot_relative_offset_does_not_map() {
        let guid = test_guid(0xEE);
        let guid_text = parser::format_guid(&guid).expect("guid");
        let volume = fixtures::fve_volume(&[fixtures::recovery_vmk(guid)]);
        let mut image = vec![0_u8; 8192];
        // 启动卷头仍在 1024；它记录的元数据相对偏移 4096 指向 5120。
        image[1024..1536].copy_from_slice(&volume[..512]);
        // 模拟动态容器：元数据块实际落在 6000，且 5120 处没有块签名。
        let block = &volume[fixtures::TEST_METADATA_RELATIVE_OFFSET as usize..];
        image[6000..6000 + block.len()].copy_from_slice(block);
        let footer = fixtures::vhd_footer(3, 1024 * 1024);
        image[8192 - 512..].copy_from_slice(&footer);

        let (_, scan, volumes, result) = analyze_slice(&image);
        assert_eq!(scan.offsets, vec![1027, 6000]);
        assert_eq!(volumes[0].status, parser::ParseStatus::NoMetadata);
        assert_eq!(volumes[1].status, parser::ParseStatus::Parsed);
        assert_eq!(volumes[1].parse_basis, parser::ParseBasis::MetadataBlock);
        let summary = &result.artifacts[0];
        let guids = attribute(summary, "bitlocker.recovery_key_guids")
            .as_array()
            .expect("guids");
        assert_eq!(guids.len(), 1);
        assert_eq!(guids[0].as_str(), Some(guid_text.as_str()));
    }

    #[test]
    fn vhdx_with_fve_reports_encrypted_and_guid() {
        let guid = test_guid(0xFF);
        let guid_text = parser::format_guid(&guid).expect("guid");
        let volume = fixtures::fve_volume(&[fixtures::recovery_vmk(guid)]);
        let mut image = fixtures::vhdx_identifier("synthetic-vhdx");
        image.resize(128 * 1024, 0);
        image[64 * 1024..64 * 1024 + volume.len()].copy_from_slice(&volume);

        let header = &image[..520];
        let format = parser::detect_format(image.len() as u64, header, None);
        assert_eq!(format.format, parser::Format::Vhdx);
        let reader = SliceReader(&image);
        let scan = parser::scan_for_signatures(&reader, 4096, 16, || Ok(())).expect("scan");
        let volumes: Vec<_> = scan
            .offsets
            .iter()
            .map(|offset| parser::parse_fve_volume(&reader, *offset))
            .collect();
        let result = build_result(
            "synthetic.vhdx",
            "file-4",
            "synthetic.vhdx",
            "application/octet-stream",
            image.len() as u64,
            &format,
            &scan,
            &volumes,
        );
        let summary = &result.artifacts[0];
        assert_eq!(
            attribute(summary, "bitlocker.format").as_str(),
            Some("vhdx")
        );
        assert_eq!(
            attribute(summary, "bitlocker.encrypted").as_bool(),
            Some(true)
        );
        let guids = attribute(summary, "bitlocker.recovery_key_guids")
            .as_array()
            .expect("guids");
        assert_eq!(guids.len(), 1);
        assert_eq!(guids[0].as_str(), Some(guid_text.as_str()));
        assert_eq!(
            attribute(summary, "vhdx.creator").as_str(),
            Some("synthetic-vhdx")
        );
    }

    #[test]
    fn synthetic_fixture_shape_is_bounded_and_generated() {
        let guid = test_guid(0xDD);
        let image = build_vhd_image(Some(guid));
        assert_eq!(image.len(), 8192);
        assert_eq!(&image[8192 - 512..8192 - 504], b"conectix");
        assert_eq!(&image[1024..1027], &[0xEB, 0x58, 0x90]);
        assert_eq!(&image[1027..1035], parser::FVE_SIGNATURE);
        assert_eq!(
            parser::format_guid(&guid).as_deref(),
            Some("40302010-6050-8070-DDDD-DDDDDDDDDDDD")
        );
        assert_eq!(
            TestVmk {
                protection_type: parser::PROTECTION_TYPE_RECOVERY_PASSWORD,
                guid,
            }
            .protection_type,
            parser::PROTECTION_TYPE_RECOVERY_PASSWORD
        );
    }
}
