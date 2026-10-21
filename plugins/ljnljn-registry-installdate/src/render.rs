//! 把 [`HiveReport`] 转成 LPP v1 结果：结果树节点（列声明）+ artifacts。
//!
//! 约定：
//! * 每条 artifact 的 `value` 是主要取值，`attributes` 保留完整证据（原值、类型、
//!   键路径、cell 偏移、文件偏移、hive 自检结论）；
//! * 每个 artifact 都带 `source.path` 与 `source.root`（单文件句柄时 `source.root`
//!   为 `file`），并附 `installdate.source` 说明来源类型；
//! * 非 ASCII 键名/值名在标题里用 `\u{XXXX}` 转义，原文仍完整保留在属性中；
//! * artifacts 总数限制在 10,000 以内（超出时加一条截断说明，不静默丢弃）。

use lovelycarve_plugin::{AnalysisResult, Artifact, Attributes, ResultColumn, ResultNode, Value};

use crate::display::escaped_if_needed;
use crate::extract::{AuxValue, HiveReport, InstallDateValue, KeyLookup, ReportNote};
use crate::regf::{filetime_unused_marker, BASE_BLOCK_SIZE};
use crate::time::filetime_to_iso8601;

/// 命名空间（artifact type 前缀）。
#[allow(dead_code)]
pub const NS: &str = "installdate";

/// hive 文件头与 regf 校验结果。
pub const ART_HIVE: &str = "installdate.hive";
/// 目标键定位。
pub const ART_KEY: &str = "installdate.key";
/// InstallDate 取值与 UTC 解析。
pub const ART_INSTALL_DATE: &str = "installdate.install_date";
/// 只读辅助值。
pub const ART_AUX_VALUE: &str = "installdate.aux_value";
/// 解析告警。
pub const ART_WARNING: &str = "installdate.warning";
/// 限制与覆盖说明。
pub const ART_LIMITATION: &str = "installdate.limitation";
/// 证据来源与定位线索。
pub const ART_EVIDENCE: &str = "installdate.evidence";

/// 单次分析产出 artifacts 的上限（宿主 LPP v1 限制为 10,000）。
pub const MAX_ARTIFACTS: usize = 10_000;

/// 全部产物类型（顺序即结果树顺序）。
pub fn artifact_types() -> &'static [&'static str] {
    &[
        ART_HIVE,
        ART_KEY,
        ART_INSTALL_DATE,
        ART_AUX_VALUE,
        ART_EVIDENCE,
        ART_WARNING,
        ART_LIMITATION,
    ]
}

/// 结果树节点（每个 artifact 类型一张表格）。
pub fn result_nodes() -> Vec<ResultNode> {
    let node = |node_type: &str, name: &str, columns: &[(&str, &str)]| ResultNode {
        node_type: node_type.to_owned(),
        name: name.to_owned(),
        columns: columns
            .iter()
            .map(|(key, label)| ResultColumn {
                key: (*key).to_owned(),
                label: (*label).to_owned(),
            })
            .collect(),
    };
    vec![
        node(
            ART_HIVE,
            "hive 与 regf 校验",
            &[
                ("installdate.file_name", "头部文件名"),
                ("installdate.file_size", "文件大小（字节）"),
                ("installdate.magic_ok", "regf 魔数通过"),
                ("installdate.regf_valid", "regf 校验结论"),
                ("installdate.version", "主/次版本"),
                ("installdate.root_cell_offset", "根键偏移"),
                ("installdate.hbins_size", "hive bins 长度"),
                ("installdate.checksum", "校验和（存储/计算）"),
                ("installdate.checksum_state", "校验和状态"),
                ("installdate.sequence", "序列号"),
                ("installdate.file_type", "文件类型"),
                ("installdate.file_format", "文件格式"),
                ("installdate.header_last_write", "头部最后写入（UTC）"),
                ("source.path", "来源文件"),
                ("source.root", "来源卷"),
            ],
        ),
        node(
            ART_KEY,
            "目标键",
            &[
                ("installdate.key_path", "目标键路径"),
                ("installdate.key_exists", "键是否存在"),
                ("installdate.resolved_path", "实际键路径"),
                ("installdate.missing_segment", "缺失段"),
                ("installdate.key_cell_offset", "键 cell 偏移"),
                ("installdate.key_file_offset", "键文件偏移"),
                ("installdate.key_last_write", "键最后写入（UTC）"),
                ("installdate.value_count", "值数量"),
                ("installdate.value_names", "值名"),
                ("source.path", "来源文件"),
                ("source.root", "来源卷"),
            ],
        ),
        node(
            ART_INSTALL_DATE,
            "安装时间（InstallDate）",
            &[
                ("installdate.state", "状态"),
                ("installdate.raw_type", "原始类型"),
                ("installdate.raw_value", "原值"),
                ("installdate.raw_hex", "十六进制原值"),
                ("installdate.utc", "UTC 时间"),
                ("installdate.raw_display", "原样表示"),
                ("installdate.plausibility", "可信度"),
                ("installdate.vk_offset", "vk cell 偏移"),
                ("installdate.data_offset", "数据 cell 偏移"),
                ("installdate.detail", "依据说明"),
                ("source.path", "来源文件"),
                ("source.root", "来源卷"),
            ],
        ),
        node(
            ART_AUX_VALUE,
            "只读辅助值",
            &[
                ("installdate.value_name", "值名"),
                ("installdate.raw_type", "类型"),
                ("installdate.raw", "取值"),
                ("installdate.vk_offset", "vk cell 偏移"),
                ("source.path", "来源文件"),
                ("source.root", "来源卷"),
            ],
        ),
        node(
            ART_EVIDENCE,
            "证据来源与定位",
            &[
                ("installdate.evidence_cell", "单元偏移"),
                ("installdate.evidence_file_offset", "文件偏移"),
                ("installdate.locator", "定位线索"),
                ("installdate.hive_file_size", "文件大小"),
                ("source.path", "来源文件"),
                ("source.root", "来源卷"),
            ],
        ),
        node(
            ART_WARNING,
            "解析告警",
            &[
                ("installdate.note_kind", "类别"),
                ("installdate.level", "级别"),
                ("installdate.detail", "详情"),
                ("source.path", "来源文件"),
                ("source.root", "来源卷"),
            ],
        ),
        node(
            ART_LIMITATION,
            "覆盖范围与限制",
            &[
                ("installdate.limitations", "限制"),
                ("installdate.detail", "说明"),
                ("source.path", "来源文件"),
                ("source.root", "来源卷"),
            ],
        ),
    ]
}

fn base_attributes(report: &HiveReport) -> Attributes {
    let mut attributes = Attributes::new();
    attributes.insert("source.path", report.source.label.as_str());
    attributes.insert("source.root", report.source.root.as_deref().unwrap_or("file"));
    attributes.insert("installdate.source", report.source.kind);
    attributes
}

fn header_artifact(report: &HiveReport) -> Artifact {
    let mut attributes = base_attributes(report);
    let header = &report.header;
    let valid = header.accepted;
    attributes.insert("installdate.file_name", header.file_name.clone().unwrap_or_default());
    attributes.insert("installdate.file_size", report.file_size);
    attributes.insert("installdate.magic_ok", header.magic_ok);
    attributes.insert("installdate.regf_valid", valid);
    attributes.insert("installdate.version", header.version.clone().unwrap_or_default());
    attributes.insert(
        "installdate.root_cell_offset",
        header
            .root_cell_offset
            .map(|value| format!("0x{value:x}"))
            .unwrap_or_default(),
    );
    attributes.insert("installdate.hbins_size", header.hbins_size.unwrap_or(0).to_string());
    attributes.insert(
        "installdate.checksum",
        match (header.checksum_stored, header.checksum_computed) {
            (Some(stored), Some(computed)) => format!("0x{stored:08x}/0x{computed:08x}"),
            _ => "(未读取)".to_owned(),
        },
    );
    attributes.insert("installdate.checksum_state", header.checksum_state);
    attributes.insert(
        "installdate.sequence",
        match header.sequence {
            Some((first, second)) => format!("{first}/{second}"),
            None => "(未读取)".to_owned(),
        },
    );
    attributes.insert("installdate.file_type", header.file_type.unwrap_or_default().to_string());
    attributes.insert("installdate.file_format", header.file_format.unwrap_or_default().to_string());
    attributes.insert(
        "installdate.header_last_write",
        header
            .last_write_utc
            .clone()
            .or_else(|| header.last_write_raw.map(filetime_unused_marker))
            .unwrap_or_else(|| "(未读取)".to_owned()),
    );
    if let Some(error) = &report.header_error {
        attributes.insert("installdate.error_code", error.kind.code());
        attributes.insert("installdate.error_offset", format!("0x{:x}", error.file_offset));
        attributes.insert("installdate.error_detail", error.detail.as_str());
    }
    let title = match &report.header_error {
        Some(error) => format!("{}：regf 校验未通过（{}）", report.source.label, error.kind.code()),
        None => format!(
            "{}：regf {}，{} 字节，校验和 {}",
            report.source.label,
            header.version.clone().unwrap_or_default(),
            report.file_size,
            match header.checksum_state {
                "match" => "一致",
                "placeholder_zero" => "为 0（未写入）",
                _ => "未比对",
            }
        ),
    };
    Artifact {
        artifact_type: ART_HIVE.to_owned(),
        title,
        value: Some(Value::from(if valid { "valid" } else { "invalid" })),
        attributes,
    }
}

fn key_artifact(report: &HiveReport) -> Artifact {
    let attributes = base_attributes(report);
    match &report.key {
        Some(key) => {
            let attributes = fill_key(attributes, key);
            Artifact {
                artifact_type: ART_KEY.to_owned(),
                title: key_title(key),
                value: Some(Value::from(if key.exists { "found" } else { "missing" })),
                attributes,
            }
        }
        None => {
            let mut attributes = attributes;
            attributes.insert("installdate.key_exists", false);
            attributes.insert("installdate.missing_segment", "(键树遍历失败)");
            Artifact {
                artifact_type: ART_KEY.to_owned(),
                title: format!("目标键 {} 未定位（hive 结构损坏）", crate::extract::TARGET_KEY),
                value: Some(Value::from("not_located")),
                attributes,
            }
        }
    }
}

fn fill_key(mut attributes: Attributes, key: &KeyLookup) -> Attributes {
    attributes.insert("installdate.key_path", crate::extract::TARGET_KEY);
    attributes.insert("installdate.key_exists", key.exists);
    attributes.insert("installdate.resolved_path", key.resolved_path.clone().unwrap_or_default());
    attributes.insert(
        "installdate.missing_segment",
        key.missing_segment.clone().unwrap_or_default(),
    );
    attributes.insert(
        "installdate.key_cell_offset",
        key.cell_offset
            .map(|value| format!("0x{value:x}"))
            .unwrap_or_default(),
    );
    attributes.insert(
        "installdate.key_file_offset",
        key.cell_offset
            .map(|value| format!("0x{:x}", BASE_BLOCK_SIZE + u64::from(value)))
            .unwrap_or_default(),
    );
    attributes.insert(
        "installdate.key_last_write",
        key.last_write_raw
            .map(|raw| {
                filetime_to_iso8601(raw).unwrap_or_else(|| filetime_unused_marker(raw))
            })
            .unwrap_or_default(),
    );
    attributes.insert(
        "installdate.value_count",
        key.value_count.map(|count| count.to_string()).unwrap_or_default(),
    );
    attributes.insert("installdate.value_names", key.value_names.join("、"));
    attributes
}

fn key_title(key: &KeyLookup) -> String {
    if key.exists {
        format!(
            "目标键存在：{}（{} 个值）",
            key.resolved_path.clone().unwrap_or_default(),
            key.value_count.unwrap_or(0)
        )
    } else {
        format!(
            "目标键缺失：缺少「{}」",
            key.missing_segment.clone().unwrap_or_default()
        )
    }
}

fn install_date_artifact(report: &HiveReport) -> Artifact {
    let value = &report.install_date;
    let mut attributes = base_attributes(report);
    attributes.insert("installdate.key_path", crate::extract::TARGET_KEY);
    attributes.insert("installdate.value_name", value.value_name.clone().unwrap_or_default());
    if let Some(name) = &value.value_name {
        if let Some(escaped) = escaped_if_needed(name) {
            attributes.insert("installdate.value_name_escaped", escaped);
        }
    }
    attributes.insert("installdate.state", value.state.code());
    attributes.insert("installdate.raw_type", value.raw_type.clone().unwrap_or_default());
    attributes.insert(
        "installdate.raw_type_code",
        value
            .raw_type_code
            .map(|code| format!("0x{code:x}"))
            .unwrap_or_default(),
    );
    attributes.insert(
        "installdate.raw_value",
        value.raw_value.map(|raw| raw.to_string()).unwrap_or_default(),
    );
    attributes.insert(
        "installdate.raw_hex",
        value
            .hex
            .clone()
            .or_else(|| value.raw_hex.clone())
            .unwrap_or_default(),
    );
    attributes.insert("installdate.utc", value.utc.clone().unwrap_or_default());
    attributes.insert(
        "installdate.raw_display",
        value.raw_display.clone().unwrap_or_default(),
    );
    attributes.insert(
        "installdate.plausibility",
        value.plausibility.map(|grade| grade.code()).unwrap_or("unsupported"),
    );
    attributes.insert(
        "installdate.vk_offset",
        value.vk_cell.map(|cell| format!("0x{cell:x}")).unwrap_or_default(),
    );
    attributes.insert(
        "installdate.vk_file_offset",
        value
            .vk_file_offset
            .map(|offset| format!("0x{offset:x}"))
            .unwrap_or_default(),
    );
    attributes.insert(
        "installdate.data_offset",
        value.data_cell.map(|cell| format!("0x{cell:x}")).unwrap_or_default(),
    );
    attributes.insert(
        "installdate.inline",
        value.inline.map(|flag| flag.to_string()).unwrap_or_default(),
    );
    attributes.insert(
        "installdate.big_data",
        value.big_data.map(|flag| flag.to_string()).unwrap_or_default(),
    );
    attributes.insert("installdate.text_hex_notation", value.text_hex_notation);
    attributes.insert("installdate.detail", value.detail.clone().unwrap_or_default());
    let title = install_title(value);
    Artifact {
        artifact_type: ART_INSTALL_DATE.to_owned(),
        title,
        value: Some(Value::from(install_value(value))),
        attributes,
    }
}

fn install_title(value: &InstallDateValue) -> String {
    match value.state {
        crate::extract::InstallState::Parsed => format!(
            "安装时间 InstallDate={} → {}（UTC）",
            value.raw_value.unwrap_or_default(),
            value.utc.clone().unwrap_or_default()
        ),
        crate::extract::InstallState::Missing => "InstallDate 缺失".to_owned(),
        crate::extract::InstallState::Unusable => format!(
            "InstallDate 不可用：{}",
            value
                .raw_value
                .map(|raw| raw.to_string())
                .unwrap_or_else(|| "无原值".to_owned())
        ),
    }
}

fn install_value(value: &InstallDateValue) -> String {
    match (&value.utc, value.raw_value) {
        (Some(utc), Some(raw)) => format!("{utc}（原值 {raw}）"),
        (None, Some(raw)) => format!("原值 {raw}（未换算）"),
        _ => value
            .detail
            .clone()
            .unwrap_or_else(|| "无原值".to_owned()),
    }
}

fn aux_artifact(report: &HiveReport, aux: &AuxValue) -> Artifact {
    let mut attributes = base_attributes(report);
    attributes.insert("installdate.key_path", crate::extract::TARGET_KEY);
    attributes.insert("installdate.value_name", aux.name.as_str());
    if let Some(escaped) = escaped_if_needed(&aux.name) {
        attributes.insert("installdate.value_name_escaped", escaped);
    }
    attributes.insert("installdate.raw_type", aux.value_type.as_str());
    attributes.insert("installdate.raw", aux.text.as_str());
    attributes.insert("installdate.vk_offset", format!("0x{:x}", aux.vk_cell));
    attributes.insert("installdate.data_offset", format!("0x{:x}", aux.data_cell));
    Artifact {
        artifact_type: ART_AUX_VALUE.to_owned(),
        title: format!("{} = {}（{}）", aux.name, aux.text, aux.value_type),
        value: Some(Value::from(aux.text.as_str())),
        attributes,
    }
}

fn evidence_artifact(report: &HiveReport) -> Artifact {
    let mut attributes = base_attributes(report);
    let value = &report.install_date;
    let cell = value.vk_cell;
    attributes.insert(
        "installdate.evidence_cell",
        cell.map(|cell| format!("0x{cell:x}")).unwrap_or_default(),
    );
    attributes.insert(
        "installdate.evidence_file_offset",
        value
            .vk_file_offset
            .map(|offset| format!("0x{offset:x}"))
            .unwrap_or_default(),
    );
    let key_cell = report.key.as_ref().and_then(|key| key.cell_offset);
    let locator = format!(
        "键 {}@cell 0x{}（文件 0x{:x}）；值 vk@cell 0x{}（文件 0x{:x}），数据 cell 0x{}；类型 {}；原值 {}",
        report
            .key
            .as_ref()
            .and_then(|key| key.resolved_path.clone())
            .unwrap_or_else(|| crate::extract::TARGET_KEY.to_owned()),
        key_cell.map(|cell| format!("{cell:x}")).unwrap_or_else(|| "—".to_owned()),
        key_cell.map(|cell| BASE_BLOCK_SIZE + u64::from(cell)).unwrap_or(0),
        cell.map(|cell| format!("{cell:x}")).unwrap_or_else(|| "—".to_owned()),
        value.vk_file_offset.unwrap_or(0),
        value
            .data_cell
            .map(|cell| format!("{cell:x}"))
            .unwrap_or_else(|| "内联/无".to_owned()),
        value.raw_type.clone().unwrap_or_else(|| "—".to_owned()),
        value
            .raw_value
            .map(|raw| raw.to_string())
            .unwrap_or_else(|| "—".to_owned()),
    );
    attributes.insert("installdate.locator", locator.as_str());
    attributes.insert("installdate.hive_file_size", report.file_size);
    Artifact {
        artifact_type: ART_EVIDENCE.to_owned(),
        title: format!("证据来源：{}", report.source.label),
        value: Some(Value::from(locator)),
        attributes,
    }
}

fn note_artifact(report: &HiveReport, note: &ReportNote) -> Artifact {
    let mut attributes = base_attributes(report);
    attributes.insert("installdate.note_kind", note.kind);
    attributes.insert(
        "installdate.level",
        match note.level {
            crate::extract::NoteLevel::Info => "info",
            crate::extract::NoteLevel::Warning => "warning",
        },
    );
    attributes.insert("installdate.detail", note.text.as_str());
    let artifact_type = if note.kind == "limitation" {
        ART_LIMITATION
    } else {
        ART_WARNING
    };
    if artifact_type == ART_LIMITATION {
        attributes.insert("installdate.limitations", note.text.as_str());
    }
    Artifact {
        artifact_type: artifact_type.to_owned(),
        title: format!("{}：{}", label_of(note.kind), truncate(&note.text, 80)),
        value: Some(Value::from(note.text.as_str())),
        attributes,
    }
}

fn label_of(kind: &str) -> &'static str {
    match kind {
        "header" => "文件头",
        "key" => "目标键",
        "value" => "值",
        "time" => "时间",
        "structure" => "结构",
        "coverage" => "覆盖范围",
        "limitation" => "限制",
        _ => "说明",
    }
}

fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_owned();
    }
    let mut out = text.chars().take(limit).collect::<String>();
    out.push('…');
    out
}

/// 生成 LPP 结果。
pub fn build_result(report: &HiveReport) -> AnalysisResult {
    let mut artifacts = Vec::with_capacity(8 + report.aux_values.len() + report.notes.len());
    artifacts.push(header_artifact(report));
    artifacts.push(key_artifact(report));
    artifacts.push(install_date_artifact(report));
    for aux in &report.aux_values {
        artifacts.push(aux_artifact(report, aux));
    }
    artifacts.push(evidence_artifact(report));
    for note in &report.notes {
        artifacts.push(note_artifact(report, note));
    }
    if artifacts.len() > MAX_ARTIFACTS {
        artifacts.truncate(MAX_ARTIFACTS - 1);
        artifacts.push(Artifact {
            artifact_type: ART_WARNING.to_owned(),
            title: "截断".to_owned(),
            value: Some(Value::from(format!("结果超过 {MAX_ARTIFACTS} 条，已截断"))),
            attributes: Attributes::new(),
        });
    }
    AnalysisResult {
        summary: Some(report.summary.clone()),
        nodes: result_nodes(),
        artifacts,
        timeline: Vec::new(),
        findings: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_types_are_unique_and_namespaced() {
        let types = artifact_types();
        for (index, name) in types.iter().enumerate() {
            assert!(name.starts_with(&format!("{NS}.")), "{name}");
            assert!(
                !types[index + 1..].iter().any(|other| other == name),
                "重复 {name}"
            );
        }
        let nodes = result_nodes();
        assert_eq!(nodes.len(), types.len());
        for node in &nodes {
            assert!(node.node_type.starts_with(&format!("{NS}.")));
            assert!(!node.columns.is_empty());
            assert!(node.columns.iter().any(|column| column.key == "source.path"));
            assert!(node.columns.iter().any(|column| column.key == "source.root"));
        }
    }

    #[test]
    fn truncation_keeps_tail_marker() {
        assert_eq!(truncate("abc", 4), "abc");
        assert_eq!(truncate("abcdef", 3), "abc…");
    }
}
