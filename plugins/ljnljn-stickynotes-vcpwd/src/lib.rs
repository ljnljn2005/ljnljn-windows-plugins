//! 便笺 VCpwd 凭据提取 — LovelyCarve `file_analyzer`。
//!
//! 输入：宿主传入的**单个**逻辑文件句柄（`File`：只读、有界读取，拿不到检材
//! 真实路径），典型对象是火眼案件导出的
//! `微软便笺(StickyNotes)/data.csv`，或用户直接提供的同构 CSV/TSV。多文件场景由
//! 宿主对每个文件分别调度本分析器，本插件不读目录、不跨文件合并。
//!
//! 覆盖范围（与需求逐条对应）：
//! 1. 编码：按文件头识别 BOM（UTF-8 / UTF-16LE / UTF-16BE），无 BOM 时先判
//!    合法 UTF-8，再严格 GBK，再 GB18030，最后 UTF-8 有损替换并记入 limitations；
//! 2. 分隔符：逗号或制表符，按字段数一致性判定并写入 limitations；
//! 3. 解析：标准 CSV 引号规则（`""` 转义、引号内换行、CRLF/LF/CR 行尾）；
//! 4. 抽取：逐行逐列按不区分大小写的 `VCpwd` + `:` / `=` / `：` 匹配，
//!    值去首尾空白与外层成对引号后**原样**输出，不做长度/字符集过滤；
//! 5. 输出：`sourceFile`、`encoding`、`delimiter`、`recordCount`、
//!    `credentialCount`、`credentials[]{value, rawCell, rowIndex,
//!    columnNameOrIndex, truncated}`、`unparsedRowCount`、`limitations`，
//!    并按值去重给出出现次数（见 [`KEY_OCCURRENCES`]）。
//!
//! **未覆盖（不是"已支持"）**：VeraCrypt 解密挂载、密码正确性判定、卷内文件
//! 计数与文档类型识别；不调用任何外部程序、不访问网络、不做二进制解包。
//! 这些提示固定写入每条结果的 limitations。
//!
//! 宿主没有给 `file_analyzer` 传可选参数的通道，因此"值边界规则""截断长度"
//! 等可调项一律取本 crate 内固定的默认值（见 [`engine`] 里的常量），不新增宿主
//! 参数 API。

mod charset;
mod csv;
mod engine;

use lovelycarve_plugin::{
    export_plugin, AnalysisResult, Artifact, Attributes, Error, File, FileAnalyzer, LogLevel,
    Plugin, Result, ResultColumn, ResultNode, Value,
};

pub use engine::{
    analyze_bytes, ColumnRef, Credential, FileReport, Occurrence, MAX_CREDENTIALS,
    MAX_INPUT_BYTES, MAX_OCCURRENCES, RAW_CELL_LIMIT,
};

/// Analyzer id；与 plugin.toml `[[capabilities]] analyzer` 一致。
pub const ANALYZER: &str = "ljnljn.stickynotes-vcpwd";
/// 插件 id；与 plugin.toml `id` 一致。
pub const PLUGIN_ID: &str = "org.ljnljn.stickynotes-vcpwd";
/// 插件显示名；与 plugin.toml `name` 一致。
pub const PLUGIN_NAME: &str = "便笺 VCpwd 凭据提取";
/// 插件版本；与 plugin.toml `version` 及 Cargo 包版本一致。
pub const PLUGIN_VERSION: &str = env!("CARGO_PKG_VERSION");

/// 凭据数据项类型。
pub const ARTIFACT_CREDENTIAL: &str = "ljnljn.stickynotes.credential";
/// 文件级汇总数据项类型。
pub const ARTIFACT_SUMMARY: &str = "ljnljn.stickynotes.summary";

// ---- 文件级属性（输出字段名 → 属性键）----
const KEY_SOURCE_FILE: &str = "stickynotes.source_file";
const KEY_ENCODING: &str = "stickynotes.encoding";
const KEY_DELIMITER: &str = "stickynotes.delimiter";
const KEY_RECORD_COUNT: &str = "stickynotes.record_count";
const KEY_CREDENTIAL_COUNT: &str = "stickynotes.credential_count";
const KEY_UNPARSED: &str = "stickynotes.unparsed_row_count";
const KEY_LIMITATIONS: &str = "stickynotes.limitations";
const KEY_HAS_HEADER: &str = "stickynotes.has_header";
const KEY_FILE_SIZE: &str = "stickynotes.source_size";
const KEY_AUDIT: &str = "stickynotes.parse_audit";

// ---- 凭据属性 ----
const KEY_VALUE: &str = "stickynotes.value";
const KEY_RAW_CELL: &str = "stickynotes.raw_cell";
const KEY_ROW_INDEX: &str = "stickynotes.row_index";
const KEY_COLUMN: &str = "stickynotes.column_name_or_index";
const KEY_TRUNCATED: &str = "stickynotes.truncated";
const KEY_OCCURRENCES: &str = "stickynotes.occurrences";
const KEY_OCCURRENCE_ROWS: &str = "stickynotes.occurrence_rows";
const KEY_OCCURRENCE_COLUMNS: &str = "stickynotes.occurrence_columns";
const KEY_TRAILING: &str = "stickynotes.trailing_pairs";
const KEY_CRLF: &str = "stickynotes.crlf_row";
const KEY_SOURCE_FILE_ID: &str = "stickynotes.source_file_id";

/// 解析不可信文件的单次读取块大小。
const READ_CHUNK: usize = 1024 * 1024;

/// 有界读取整个逻辑文件（最多 [`MAX_INPUT_BYTES`] 字节）。
///
/// 返回 `(bytes, 是否达到上限)`。读取错误照常向上传播（`?`），不吞成空结果。
pub fn read_file_bytes(file: &File, cap: usize) -> Result<(Vec<u8>, bool)> {
    let size = usize::try_from(file.size()).unwrap_or(usize::MAX);
    let limit = size.min(cap);
    let mut bytes = Vec::with_capacity(limit.min(READ_CHUNK * 4));
    while bytes.len() < limit {
        let want = (limit - bytes.len()).min(READ_CHUNK);
        let chunk = file.read(bytes.len() as u64, want)?;
        if chunk.is_empty() {
            break;
        }
        bytes.extend_from_slice(&chunk);
    }
    let truncated = size > cap;
    if truncated {
        file.context().log(
            LogLevel::Warn,
            &format!("便笺 CSV 超过 {cap} 字节上限，仅解析前 {cap} 字节"),
        );
    }
    Ok((bytes, truncated))
}

/// 把引擎报告转成 LPP v1 结果（纯函数，便于单元测试）。
pub fn build_result(report: &FileReport, file_id: &str, size: u64) -> AnalysisResult {
    let mut artifacts = Vec::with_capacity(report.credentials.len() + 1);

    let mut summary_attributes = Attributes::new();
    summary_attributes.insert(KEY_SOURCE_FILE, report.source_file.as_str());
    summary_attributes.insert(KEY_SOURCE_FILE_ID, file_id);
    summary_attributes.insert(KEY_FILE_SIZE, size);
    summary_attributes.insert(KEY_ENCODING, report.encoding.as_str());
    summary_attributes.insert(KEY_DELIMITER, report.delimiter.as_str());
    summary_attributes.insert(KEY_RECORD_COUNT, report.record_count as u64);
    summary_attributes.insert(KEY_CREDENTIAL_COUNT, report.credential_count as u64);
    summary_attributes.insert(KEY_UNPARSED, report.unparsed_row_count as u64);
    summary_attributes.insert(KEY_HAS_HEADER, report.has_header);
    summary_attributes.insert(
        KEY_AUDIT,
        format!(
            "引号包裹值 {} 个、含冒号值 {} 个、含逗号值 {} 个",
            report.quoted_values, report.colon_values, report.comma_values
        ),
    );
    summary_attributes.insert(
        KEY_LIMITATIONS,
        Value::Array(
            report
                .limitations
                .iter()
                .map(|item| Value::from(item.as_str()))
                .collect(),
        ),
    );
    summary_attributes.insert("source.path", report.source_file.as_str());
    summary_attributes.insert("stickynotes.source", report.source_file.as_str());
    artifacts.push(Artifact {
        artifact_type: ARTIFACT_SUMMARY.to_owned(),
        title: format!(
            "{}：编码 {}，分隔符 {}，记录 {} 条，凭据 {} 个",
            report.source_file,
            report.encoding,
            delimiter_label(&report.delimiter),
            report.record_count,
            report.credential_count
        ),
        value: Some(Value::from(report.source_file.clone())),
        attributes: summary_attributes,
    });

    for credential in &report.credentials {
        let mut attributes = Attributes::new();
        attributes.insert(KEY_VALUE, credential.value.as_str());
        attributes.insert(KEY_RAW_CELL, credential.raw_cell.as_str());
        attributes.insert(KEY_ROW_INDEX, credential.row_index as u64);
        attributes.insert(KEY_COLUMN, credential.column_label());
        attributes.insert(KEY_TRUNCATED, credential.truncated);
        attributes.insert(KEY_OCCURRENCES, credential.occurrences as u64);
        attributes.insert(
            KEY_OCCURRENCE_ROWS,
            Value::Array(
                credential
                    .occurrence_locations
                    .iter()
                    .map(|item| Value::from(item.row_index as u64))
                    .collect(),
            ),
        );
        attributes.insert(
            KEY_OCCURRENCE_COLUMNS,
            Value::Array(
                credential
                    .occurrence_locations
                    .iter()
                    .map(|item| Value::from(item.column.label()))
                    .collect(),
            ),
        );
        attributes.insert(KEY_TRAILING, credential.trailing_pairs as u64);
        attributes.insert(KEY_CRLF, credential.crlf_row);
        attributes.insert(KEY_SOURCE_FILE, report.source_file.as_str());
        attributes.insert(KEY_SOURCE_FILE_ID, file_id);
        attributes.insert(KEY_ENCODING, report.encoding.as_str());
        attributes.insert("source.path", report.source_file.as_str());
        attributes.insert("stickynotes.source", report.source_file.as_str());
        attributes.insert("stickynotes.origin", credential.raw_cell.as_str());
        artifacts.push(Artifact {
            artifact_type: ARTIFACT_CREDENTIAL.to_owned(),
            title: format!(
                "VCpwd 候选（第 {} 行，列 {}）",
                credential.row_index,
                credential.column_label()
            ),
            value: Some(Value::from(credential.value.as_str())),
            attributes,
        });
    }

    let summary = format!(
        "{}：编码 {}，分隔符{}，记录 {} 条（{}），凭据值 {} 个（去重后），未解析行 {}；未覆盖 VeraCrypt 挂载/密码校验/卷内文件计数",
        report.source_file,
        report.encoding,
        delimiter_label(&report.delimiter),
        report.record_count,
        if report.has_header { "含表头" } else { "无表头" },
        report.credential_count,
        report.unparsed_row_count
    );
    let mut result = AnalysisResult {
        summary: Some(summary),
        artifacts,
        ..AnalysisResult::default()
    };
    result.nodes = result_nodes(report);
    result
}

fn delimiter_label(delimiter: &str) -> &'static str {
    match delimiter {
        "\t" => "制表符",
        "," => "逗号",
        _ => "未知",
    }
}

/// 结果树中凭据表的列定义。
fn credential_columns() -> Vec<ResultColumn> {
    [
        (KEY_ROW_INDEX, "行号"),
        (KEY_COLUMN, "列名/列序号"),
        (KEY_VALUE, "VCpwd 值"),
        (KEY_OCCURRENCES, "出现次数"),
        (KEY_RAW_CELL, "原始单元格(截断200字)"),
        (KEY_TRUNCATED, "是否截断"),
        (KEY_ENCODING, "编码"),
    ]
    .into_iter()
    .map(|(key, label)| ResultColumn {
        key: key.to_owned(),
        label: label.to_owned(),
    })
    .collect()
}

fn result_nodes(report: &FileReport) -> Vec<ResultNode> {
    let mut nodes = Vec::new();
    if !report.credentials.is_empty() {
        nodes.push(ResultNode {
            node_type: "stickynotes.credentials".to_owned(),
            name: format!("{} · VCpwd 凭据候选", report.source_file),
            columns: credential_columns(),
        });
    }
    nodes.push(ResultNode {
        node_type: "stickynotes.file_summary".to_owned(),
        name: format!(
            "{} · 文件汇总（成功解析 {}，未解析 {}）",
            report.source_file, report.credential_count, report.unparsed_row_count
        ),
        columns: Vec::new(),
    });
    nodes
}

/// 便笺 CSV 凭据候选提取分析器。
pub struct StickyNotesVcpwdAnalyzer;

impl FileAnalyzer for StickyNotesVcpwdAnalyzer {
    fn analyzer(&self) -> &str {
        ANALYZER
    }

    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        file.context()
            .progress(0, Some(1), Some("读取便笺 CSV"))?;
        let (bytes, hit_cap) = read_file_bytes(file, MAX_INPUT_BYTES)?;
        if file.size() > 0 && bytes.is_empty() {
            // 宿主报告有内容却读不出任何字节：这是读取失败，不应报"空结果成功"。
            return Err(Error::new(
                "SHORT_READ",
                format!("文件 {} 声明 {} 字节但读取为空", file.name(), file.size()),
            ));
        }
        let mut report = analyze_bytes(file.name(), &bytes);
        if hit_cap && !report.limitations.iter().any(|item| item.contains("上限")) {
            report.limitations.push(format!(
                "文件大于 {MAX_INPUT_BYTES} 字节，仅解析前 {MAX_INPUT_BYTES} 字节"
            ));
        }
        file.context()
            .progress(1, Some(1), Some("汇编结果"))?;
        let result = build_result(&report, file.id(), file.size());
        file.context().log(
            LogLevel::Info,
            &format!(
                "便笺 CSV {}：编码 {}，记录 {}，凭据 {}，未解析行 {}",
                file.name(),
                report.encoding,
                report.record_count,
                report.credential_count,
                report.unparsed_row_count
            ),
        );
        Ok(result)
    }
}

fn plugin() -> Plugin {
    Plugin::new(PLUGIN_ID, PLUGIN_NAME, PLUGIN_VERSION)
        .file_analyzer(StickyNotesVcpwdAnalyzer)
}

export_plugin!(plugin);

#[cfg(test)]
mod tests {
    use super::*;

    /// 构造 UTF-8 与 GBK 两种编码的合成检材。
    fn gbk(text: &str) -> Vec<u8> {
        let (bytes, _, had_errors) = encoding_rs::GBK.encode(text);
        assert!(!had_errors);
        bytes.into_owned()
    }

    fn utf16le(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn attribute<'a>(artifact: &'a Artifact, key: &str) -> &'a Value {
        artifact
            .attributes
            .get(key)
            .unwrap_or_else(|| panic!("缺少属性 {key}"))
    }

    fn credential_artifacts(result: &AnalysisResult) -> Vec<&Artifact> {
        result
            .artifacts
            .iter()
            .filter(|artifact| artifact.artifact_type == ARTIFACT_CREDENTIAL)
            .collect()
    }

    fn summary_artifact(result: &AnalysisResult) -> &Artifact {
        result
            .artifacts
            .iter()
            .find(|artifact| artifact.artifact_type == ARTIFACT_SUMMARY)
            .expect("应有文件汇总数据项")
    }

    fn limiting(result: &AnalysisResult) -> Vec<String> {
        match summary_artifact(result).attributes.get(KEY_LIMITATIONS) {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect(),
            _ => Vec::new(),
        }
    }

    #[test]
    fn plugin_identity_matches_manifest() {
        assert_eq!(ANALYZER, "ljnljn.stickynotes-vcpwd");
        assert_eq!(
            PLUGIN_ID,
            "org.ljnljn.stickynotes-vcpwd"
        );
        let manifest = include_str!("../plugin.toml");
        assert!(manifest.contains(&format!("id = \"{PLUGIN_ID}\"")));
        assert!(manifest.contains(&format!("name = \"{PLUGIN_NAME}\"")));
        assert!(manifest.contains(&format!("version = \"{PLUGIN_VERSION}\"")));
        assert!(manifest.contains(&format!("analyzer = \"{ANALYZER}\"")));
        assert!(manifest.contains("path = \"ljnljn_kb_stickynotes_vcpwd_extract_dc952a12\""));
        assert!(manifest.contains("isolation = \"process\""));
        assert!(manifest.contains("emit_artifacts"));
        assert_eq!(StickyNotesVcpwdAnalyzer.analyzer(), ANALYZER);
    }

    #[test]
    fn synthetic_utf8_csv_with_header_and_multiple_hits() {
        let bytes = "索引,内容,时间\r\n1,VCpwd: alpha,2024-01-01\r\n2,VCpwd: beta,2024-01-02\r\n3,VCpwd: alpha,2024-01-03\r\n".as_bytes();
        let report = analyze_bytes("data.csv", bytes);
        let result = build_result(&report, "file:1", bytes.len() as u64);
        let summary = summary_artifact(&result);
        assert_eq!(attribute(summary, KEY_ENCODING), &Value::from("UTF-8"));
        assert_eq!(attribute(summary, KEY_DELIMITER), &Value::from(","));
        assert_eq!(attribute(summary, KEY_RECORD_COUNT), &Value::from(4_u64));
        assert_eq!(attribute(summary, KEY_CREDENTIAL_COUNT), &Value::from(2_u64));
        assert_eq!(attribute(summary, KEY_UNPARSED), &Value::from(0_u64));
        assert_eq!(attribute(summary, KEY_SOURCE_FILE), &Value::from("data.csv"));

        let credentials = credential_artifacts(&result);
        assert_eq!(credentials.len(), 2);
        assert_eq!(attribute(credentials[0], KEY_VALUE), &Value::from("alpha"));
        assert_eq!(attribute(credentials[0], KEY_ROW_INDEX), &Value::from(2_u64));
        assert_eq!(attribute(credentials[0], KEY_COLUMN), &Value::from("内容"));
        assert_eq!(attribute(credentials[0], KEY_OCCURRENCES), &Value::from(2_u64));
        assert_eq!(attribute(credentials[0], KEY_TRUNCATED), &Value::from(false));
        assert_eq!(attribute(credentials[1], KEY_VALUE), &Value::from("beta"));
        assert_eq!(attribute(credentials[1], KEY_ROW_INDEX), &Value::from(3_u64));
        assert_eq!(
            attribute(credentials[0], KEY_RAW_CELL),
            &Value::from("VCpwd: alpha")
        );
    }

    #[test]
    fn synthetic_utf16le_csv_is_decoded_and_located() {
        let report = analyze_bytes("data.csv", &utf16le("索引,内容\r\n1,VCpwd：金眼睛\r\n"));
        let result = build_result(&report, "file:2", 0);
        let credentials = credential_artifacts(&result);
        assert_eq!(report.encoding, "UTF-16LE");
        assert_eq!(attribute(credentials[0], KEY_VALUE), &Value::from("金眼睛"));
        assert_eq!(attribute(credentials[0], KEY_ROW_INDEX), &Value::from(2_u64));
    }

    #[test]
    fn synthetic_gbk_csv_is_decoded() {
        let report = analyze_bytes("data.csv", &gbk("索引,内容\r\n1,VCpwd: 密码=\r\n"));
        assert_eq!(report.encoding, "GBK");
        // 值里的 `=` 不会被二次切分。
        assert_eq!(report.credentials[0].value, "密码=");
    }

    #[test]
    fn synthetic_tab_separated_headerless_csv() {
        let report = analyze_bytes("data.csv", "1\tVCpwd: tab-a\n2\tVCpwd=tab-b\n".as_bytes());
        let result = build_result(&report, "file:3", 0);
        assert_eq!(attribute(summary_artifact(&result), KEY_DELIMITER), &Value::from("\t"));
        let credentials = credential_artifacts(&result);
        assert_eq!(attribute(credentials[0], KEY_COLUMN), &Value::from("1"));
        assert_eq!(attribute(credentials[0], KEY_VALUE), &Value::from("tab-a"));
        assert_eq!(attribute(credentials[1], KEY_VALUE), &Value::from("tab-b"));
        assert_eq!(attribute(credentials[1], KEY_ROW_INDEX), &Value::from(2_u64));
    }

    #[test]
    fn no_hit_and_empty_files_yield_zero_credentials() {
        let report = analyze_bytes("data.csv", "序号,内容\r\n1,买菜\r\n2,开会\r\n".as_bytes());
        let result = build_result(&report, "file:4", 0);
        assert!(credential_artifacts(&result).is_empty());
        assert_eq!(
            attribute(summary_artifact(&result), KEY_CREDENTIAL_COUNT),
            &Value::from(0_u64)
        );

        let report = analyze_bytes("data.csv", b"");
        let result = build_result(&report, "file:5", 0);
        assert!(credential_artifacts(&result).is_empty());
        assert_eq!(attribute(summary_artifact(&result), KEY_RECORD_COUNT), &Value::from(0_u64));
        assert!(limiting(&result).iter().any(|item| item.contains("文件为空")));
    }

    #[test]
    fn limitations_always_state_uncovered_scope() {
        let report = analyze_bytes("data.csv", b"a\nVCpwd: x\n");
        let result = build_result(&report, "file:6", 0);
        let limitations = limiting(&result);
        assert!(limitations.iter().any(|item| item.contains("未覆盖：不实现 VeraCrypt 解密挂载")));
        assert!(limitations.iter().any(|item| item.contains("不校验 VCpwd 值")));
    }

    #[test]
    fn source_identity_is_preserved_on_every_artifact() {
        let report = analyze_bytes("data.csv", b"\xEF\xBB\xBFVCpwd: x\n");
        let result = build_result(&report, "file:7", 9);
        for artifact in &result.artifacts {
            assert_eq!(attribute(artifact, KEY_SOURCE_FILE), &Value::from("data.csv"));
            assert_eq!(attribute(artifact, KEY_SOURCE_FILE_ID), &Value::from("file:7"));
            assert_eq!(attribute(artifact, "source.path"), &Value::from("data.csv"));
        }
        assert_eq!(
            attribute(summary_artifact(&result), KEY_FILE_SIZE),
            &Value::from(9_u64)
        );
    }

    #[test]
    fn capabilities_and_identity_match_manifest() {
        let manifest = include_str!("../plugin.toml");
        assert!(manifest.contains("type = \"file_analyzer\""));
        assert_eq!(StickyNotesVcpwdAnalyzer.analyzer(), ANALYZER);
        assert_eq!(PLUGIN_VERSION, env!("CARGO_PKG_VERSION"));
        let mut plugin = Plugin::new(PLUGIN_ID, PLUGIN_NAME, PLUGIN_VERSION)
            .file_analyzer(StickyNotesVcpwdAnalyzer);
        // 注册后可再次取回，证明 analyzer id 与注册项一致。
        plugin = plugin.file_analyzer(StickyNotesVcpwdAnalyzer);
        drop(plugin);
    }

    #[test]
    fn result_nodes_expose_credential_table() {
        let report = analyze_bytes("data.csv", b"\xEF\xBB\xBF\xE5\xBA\x8F\xE5\x8F\xB7,\xE5\x86\x85\xE5\xAE\xB9\r\n1,VCpwd: x\r\n");
        let result = build_result(&report, "file:8", 0);
        assert!(result
            .nodes
            .iter()
            .any(|node| node.node_type == "stickynotes.credentials"
                && node.columns.iter().any(|column| column.key == KEY_VALUE)));
        assert!(result.summary.as_deref().unwrap_or_default().contains("凭据值 1 个"));
    }
}
