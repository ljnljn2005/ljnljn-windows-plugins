//! LovelyCarve 单文件分析器：腾讯 QQ 安装日志 `qq_setup.log` 时间片段与标记定位。
//!
//! 离线最小能力，只做三件事：
//!
//! 1. 读取单个 `qq_setup.log` 的**字节**（UTF-8 含 BOM → GBK → 替换字符降级），
//! 2. 用正则 `\d{4}/\d{6}` 抽取 `mmdd/hhmmss` 片段并原样保留，
//! 3. 在同行做大小写不敏感关键字分类（install / complete / launch / other）。
//!
//! 不做：跨年推断、使用时段结论、与安装软件或最近访问 csv 关联、`QQ.exe` 版本
//! 校验、时区换算。这些缺口同时写入结果 `limitations` 与 `findings`。
//!
//! 运行时只通过 SDK 的 [`File`] 逻辑句柄读检材（只读、有界），不接触宿主路径、
//! 不执行检材内的任何命令、不联网。
//!
//! ## 输出字段（每条事件 artifact 一个字段，键统一前缀 `qqsetup.`）
//!
//! | 字段 | artifact 位置 | 说明 |
//! | --- | --- | --- |
//! | `filePath` | 文件级汇总 artifact `qqsetup.file` 的 `qqsetup.file_path` | 日志的检材内逻辑路径 |
//! | `encoding` | `qqsetup.encoding` | `utf-8` / `gbk` / `utf-8-lossy` |
//! | `lineCount` | `qqsetup.line_count` | 物理行数（1 起算的行号上界） |
//! | `eventCount` | `qqsetup.event_count` | 事件条数 |
//! | `unparsedLineCount` | `qqsetup.unparsed_line_count` | 无时间片段的行数（含空行） |
//! | `limitations` | `qqsetup.limitations`（数组）+ `findings` | 解析限制与注意事项 |
//! | `events[].lineNo` | `qqsetup.line_no` | 1 起算日志行号 |
//! | `events[].timeRaw` | `qqsetup.time_raw` | 命中的原始文本，如 `0831/180025` |
//! | `events[].month/day/hour/minute/second` | `qqsetup.month` … | 拆出的整数，越界原样保留 |
//! | `events[].category` | `qqsetup.category` | install / complete / launch / other |
//! | `events[].lineText` | `qqsetup.line_text` | 原始行文本，截断到 200 字符 |
//! | `events[].sourceRef` | `source.path` + `qqsetup.source_ref` | 可复核定位，如 `qq_setup.log#L3` |
//!
//! 另外每条事件保留 `qqsetup.category_hits`（同行命中类别全集）、
//! `qqsetup.char_offset`（片段在原始行中的字符偏移）、`qqsetup.line_chars`（截断前
//! 字符数），用于回溯截断与同一行多片段的情况。

mod parser;

use lovelycarve_plugin::{
    AnalysisResult, Artifact, Attributes, Error, File, FileAnalyzer, Finding, LogLevel, Plugin,
    Result, ResultColumn, ResultNode, Severity, Value,
};

/// 与 plugin.toml 的 `[library].path` 无关，是插件身份：必须与 plugin.toml `id` 一致。
pub const PLUGIN_ID: &str = "org.ljnljn.qq-setup-log";
pub const PLUGIN_NAME: &str = "QQ安装日志时间片段";
/// 必须与 plugin.toml `[[capabilities]].analyzer` 一致。
pub const ANALYZER: &str = "ljnljn.qq-setup-log";

/// 事件 artifact 类型。
pub const EVENT_TYPE: &str = "qqsetup.event";
/// 文件级汇总 artifact 类型。
pub const FILE_TYPE: &str = "qqsetup.file";

/// 宿主对单次分析结果的上限（LPP v1：最多 10000 项）。
const MAX_RESULT_ITEMS: usize = 10_000;

/// 可选的 `sourceRef` 前缀：宿主只给出显示名，不下发真实路径，因此默认取
/// `file.name()`；无法获取名称时退化为固定占位符。
fn source_base(file: &File) -> String {
    let name = file.name().trim();
    if name.is_empty() {
        format!("file:{}", file.id())
    } else {
        name.replace('\\', "/")
    }
}

/// 把一次解析结果转成 LPP 结果对象。
pub fn build_result(file: &File, bytes: &[u8]) -> Result<AnalysisResult> {
    let base = source_base(file);
    let timeline = parser::parse(bytes, &base)
        .map_err(|message| Error::new("RESOURCE_LIMIT", format!("{base} 未解析：{message}")))?;

    if timeline.events.len() + 1 > MAX_RESULT_ITEMS {
        return Err(Error::new(
            "RESOURCE_LIMIT",
            format!(
                "{} 解析出 {} 条事件，超过单次分析 {} 项的上限；未返回部分结果，请先按行拆分日志",
                base,
                timeline.events.len(),
                MAX_RESULT_ITEMS
            ),
        ));
    }

    let mut summary_attributes: Attributes = [
        ("source.path", Value::from(base.as_str())),
        ("source.file_id", Value::from(file.id())),
        ("qqsetup.source", Value::from(base.as_str())),
        ("qqsetup.file_path", Value::from(base.as_str())),
        ("qqsetup.file_name", Value::from(file.name())),
        ("qqsetup.encoding", Value::from(timeline.encoding.encoding_label())),
        ("qqsetup.line_count", Value::from(timeline.line_count as u64)),
        ("qqsetup.event_count", Value::from(timeline.events.len() as u64)),
        (
            "qqsetup.unparsed_line_count",
            Value::from(timeline.unparsed_line_count as u64),
        ),
        (
            "qqsetup.blank_line_count",
            Value::from(timeline.blank_line_count as u64),
        ),
    ]
    .into_iter()
    .collect();
    summary_attributes.insert(
        "qqsetup.limitations",
        Value::Array(
            timeline
                .limitations
                .iter()
                .map(|note| Value::from(note.as_str()))
                .collect(),
        ),
    );

    let mut artifacts = Vec::with_capacity(timeline.events.len() + 1);
    artifacts.push(Artifact {
        artifact_type: FILE_TYPE.to_string(),
        title: format!("{base} 安装日志时间片段"),
        value: Some(Value::from(base.as_str())),
        attributes: summary_attributes,
    });

    for event in &timeline.events {
        let source_ref = format!("{base}#L{}", event.line_no);
        let mut attributes: Attributes = [
            ("source.path", Value::from(base.as_str())),
            ("source.file_id", Value::from(file.id())),
            ("qqsetup.source", Value::from(base.as_str())),
            ("qqsetup.source_ref", Value::from(source_ref.as_str())),
            ("qqsetup.line_no", Value::from(event.line_no as u64)),
            ("qqsetup.time_raw", Value::from(event.time_raw.as_str())),
            ("qqsetup.month", Value::from(u64::from(event.month))),
            ("qqsetup.day", Value::from(u64::from(event.day))),
            ("qqsetup.hour", Value::from(u64::from(event.hour))),
            ("qqsetup.minute", Value::from(u64::from(event.minute))),
            ("qqsetup.second", Value::from(u64::from(event.second))),
            ("qqsetup.category", Value::from(event.category.as_str())),
            ("qqsetup.line_text", Value::from(event.line_text.as_str())),
            ("qqsetup.encoding", Value::from(timeline.encoding.encoding_label())),
        ]
        .into_iter()
        .collect();
        attributes.insert(
            "qqsetup.category_hits",
            Value::Array(
                event
                    .category_hits
                    .iter()
                    .map(|category| Value::from(category.as_str()))
                    .collect(),
            ),
        );
        attributes.insert(
            "qqsetup.char_offset",
            Value::from(event.char_offset as u64),
        );
        attributes.insert(
            "qqsetup.line_chars",
            Value::from(event.line_chars as u64),
        );
        attributes.insert(
            "qqsetup.time_basis",
            Value::from("mmdd/hhmmss 原值，未补年份、未做时区换算"),
        );
        artifacts.push(Artifact {
            artifact_type: EVENT_TYPE.to_string(),
            title: format!(
                "第{}行 {} {}",
                event.line_no,
                event.time_raw,
                event.category.as_str()
            ),
            value: Some(Value::from(event.time_raw.as_str())),
            attributes,
        });
    }

    let mut counts = std::collections::BTreeMap::new();
    for event in &timeline.events {
        *counts.entry(event.category.as_str()).or_insert(0_u64) += 1;
    }
    let breakdown = if counts.is_empty() {
        "无".to_string()
    } else {
        counts
            .iter()
            .map(|(category, count)| format!("{category} {count}"))
            .collect::<Vec<_>>()
            .join("、")
    };

    let mut findings = vec![Finding {
        severity: Severity::Info,
        title: "解析范围与未覆盖项".to_string(),
        description: "仅解析 mmdd/hhmmss 片段与同行安装/完成/启动标记并原样列出；未补年份、未做时区换算、未推断 QQ 使用时段、未关联安装软件或最近访问 csv、未校验 QQ.exe 版本。".to_string(),
        attributes: [
            ("qqsetup.source", Value::from(base.as_str())),
            ("qqsetup.encoding", Value::from(timeline.encoding.encoding_label())),
        ]
        .into_iter()
        .collect(),
    }];
    if timeline.encoding != parser::DecodePath::Utf8 {
        findings.push(Finding {
            severity: Severity::Low,
            title: format!("日志编码为 {}", timeline.encoding.encoding_label()),
            description: timeline
                .limitations
                .iter()
                .find(|note| note.contains("GBK") || note.contains("U+FFFD"))
                .cloned()
                .unwrap_or_else(|| "解码路径不是严格 UTF-8，请复核相关行的原文".to_string()),
            attributes: [("qqsetup.source", Value::from(base.as_str()))]
                .into_iter()
                .collect(),
        });
    }

    let summary = format!(
        "{base}：编码 {}，共 {} 行，{} 条时间事件（{}），{} 行无时间片段。仅原文定位，不推断年份、时区与使用时段。",
        timeline.encoding.encoding_label(),
        timeline.line_count,
        timeline.events.len(),
        breakdown,
        timeline.unparsed_line_count
    );

    Ok(AnalysisResult {
        summary: Some(summary),
        nodes: result_nodes(&timeline),
        artifacts,
        timeline: Vec::new(),
        findings,
    })
}

/// 结果树：文件级汇总 + 按日志行序排列的事件表。
fn result_nodes(timeline: &parser::Timeline) -> Vec<ResultNode> {
    let mut nodes = vec![ResultNode {
        node_type: FILE_TYPE.to_string(),
        name: "安装日志文件".to_string(),
        columns: columns(&[
            ("qqsetup.file_source", "来源文件"),
            ("qqsetup.encoding", "编码"),
            ("qqsetup.line_count", "总行数"),
            ("qqsetup.event_count", "时间事件数"),
            ("qqsetup.unparsed_line_count", "无时间行数"),
            ("qqsetup.blank_line_count", "空行数"),
        ]),
    }];
    if timeline.events.is_empty() {
        return nodes;
    }
    let event_columns = columns(&[
        ("qqsetup.line_no", "行号"),
        ("qqsetup.time_raw", "时间原文"),
        ("qqsetup.month", "月"),
        ("qqsetup.day", "日"),
        ("qqsetup.hour", "时"),
        ("qqsetup.minute", "分"),
        ("qqsetup.second", "秒"),
        ("qqsetup.category", "分类"),
        ("qqsetup.line_text", "原始行"),
        ("qqsetup.source_ref", "来源定位"),
    ]);
    nodes.push(ResultNode {
        node_type: EVENT_TYPE.to_string(),
        name: "安装日志时间事件".to_string(),
        columns: event_columns,
    });
    nodes
}

fn columns(spec: &[(&str, &str)]) -> Vec<ResultColumn> {
    spec.iter()
        .map(|(key, label)| ResultColumn {
            key: (*key).to_string(),
            label: (*label).to_string(),
        })
        .collect()
}

/// `file_analyzer`：`analyzer` 返回值必须与 plugin.toml 的 capabilities 一致。
pub struct QqSetupTimeline;

impl FileAnalyzer for QqSetupTimeline {
    fn analyzer(&self) -> &str {
        ANALYZER
    }

    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        file.context().check_cancelled()?;
        if file.size() > parser::MAX_INPUT_BYTES as u64 {
            return Err(Error::new(
                "RESOURCE_LIMIT",
                format!(
                    "{} 大小 {} 字节超过 {} 字节上限；未解析（不截断以免行计数不完整）",
                    source_base(file),
                    file.size(),
                    parser::MAX_INPUT_BYTES
                ),
            ));
        }
        let bytes = file.read(0, file.size() as usize)?;
        if bytes.len() as u64 != file.size() {
            return Err(Error::new(
                "SHORT_READ",
                format!(
                    "{} 只读到 {} / {} 字节，拒绝在不完整数据上解析",
                    source_base(file),
                    bytes.len(),
                    file.size()
                ),
            ));
        }
        file.context().check_cancelled()?;
        let result = build_result(file, &bytes)?;
        file.context().log(
            LogLevel::Info,
            &format!(
                "qq_setup.log 解析完成：{}",
                result.summary.clone().unwrap_or_default()
            ),
        );
        Ok(result)
    }
}

fn plugin() -> Plugin {
    Plugin::new(PLUGIN_ID, PLUGIN_NAME, env!("CARGO_PKG_VERSION")).file_analyzer(QqSetupTimeline)
}

lovelycarve_plugin::export_plugin!(plugin);

#[cfg(test)]
mod tests {
    use super::*;

    /// 合成日志 #1：安装完成启动完整流程（UTF-8 无 BOM，CRLF）。
    ///
    /// 所有取值均为自编，刻意不复用知识快照里的旧案件值（版本号、QQ.exe、data.csv 等）。
    const SYNTH_FULL_FLOW: &str = concat!(
        "0831/180025 [Setup] 开始安装 合成样本\r\n",
        "0831/180026 [Install] 正在安装 组件 Core\r\n",
        "0831/180708 [Complete] 安装完成 Success\r\n",
        "0831/180708 Show QQ Window\r\n",
        "0831/180709 [Launch] launch app.exe\r\n",
    );

    /// 合成日志 #2：缺完成标记（安装后直接启动，末行无时间戳）。
    const SYNTH_MISSING_COMPLETE: &str = concat!(
        "0912/101500 Setup begin\r\n",
        "0912/101659 Install files copied\r\n",
        "0912/101700 Show QQ Window\r\n",
        "0912/101701 show qq window again\r\n",
        "startup finished without marker\r\n",
    );

    /// 合成日志 #3：乱码场景 + 边界值。
    ///
    /// 结构（行序即断言顺序）：
    /// 1. BOM + ASCII 安装行
    /// 2. GBK 中文「安装完成」行
    /// 3. 不可恢复的非法字节段（单独一行）
    /// 4. 越界的月日/时分秒（照常输出）
    ///
    /// 注意：GBK 字节在合法 UTF-8 里不存在，本样例因此整体只能走「替换字符降级」；
    /// 同一份文件里 GBK 行与坏字节行并存时，GBK 行会被显示成乱码（见 README 限制）。
    fn synth_garbled() -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]); // 带 UTF-8 BOM
        bytes.extend_from_slice(b"0913/090000 SETUP start\r\n");
        bytes.extend_from_slice(b"0913/090010 \xB0\xB2\xD7\xB0\xCD\xEA\xB3\xC9\r\n"); // GBK「安装完成」
        bytes.extend_from_slice(&[0xFF, 0xF5, 0x81, 0xFF]); // 非法字节段（替换字符）
        bytes.extend_from_slice(b"\r\n");
        bytes.extend_from_slice(b"1332/256199 Install overrun values\r\n");
        bytes
    }

    fn parse_sample(bytes: &[u8]) -> parser::Timeline {
        parser::parse(bytes, "qq_setup.log").expect("sample within cap")
    }

    #[test]
    fn identity_matches_manifest_expectations() {
        assert_eq!(PLUGIN_ID, "org.ljnljn.qq-setup-log");
        assert_eq!(ANALYZER, "ljnljn.qq-setup-log");
        assert_eq!(EVENT_TYPE, "qqsetup.event");
        assert_eq!(env!("CARGO_PKG_NAME"), "ljnljn-qq-setup-timeline-d569c0d3");
        // 构造函数能装配出插件实例（身份在 Plugin::new 中传入）。
        let _ = plugin();
    }

    #[test]
    fn synthetic_samples_do_not_reuse_old_case_values() {
        // 知识快照 mvm5sa56... 的旧案件取值（QQ 版本号、QQ.exe、两个 csv 路径）不得出现在样例里，
        // 避免把旧答案当作本插件的结论。样例只验证解析规则。
        let all = [SYNTH_FULL_FLOW, SYNTH_MISSING_COMPLETE].join("");
        let garbled = String::from_utf8_lossy(&synth_garbled()).into_owned();
        for haystack in [all, garbled] {
            for forbidden in ["9.9.33", "QQ.exe", "data.csv", "Tencent Files"] {
                assert!(
                    !haystack.contains(forbidden),
                    "样例不得包含旧案件取值 {forbidden}"
                );
            }
        }
    }

    #[test]
    fn analyzer_name_is_stable() {
        assert_eq!(QqSetupTimeline.analyzer(), ANALYZER);
    }

    #[test]
    fn sample_full_flow_keeps_line_numbers_and_categories() {
        let timeline = parse_sample(SYNTH_FULL_FLOW.as_bytes());
        assert_eq!(timeline.encoding, parser::DecodePath::Utf8);
        assert_eq!(timeline.line_count, 5);
        assert_eq!(timeline.events.len(), 5);
        assert_eq!(timeline.unparsed_line_count, 0);

        let expected = [
            (1, "0831/180025", parser::Category::Install),
            (2, "0831/180026", parser::Category::Install),
            (3, "0831/180708", parser::Category::Complete),
            (4, "0831/180708", parser::Category::Launch),
            (5, "0831/180709", parser::Category::Launch),
        ];
        for (event, (line_no, time_raw, category)) in timeline.events.iter().zip(expected) {
            assert_eq!(event.line_no, line_no, "lineNo must equal the physical log line");
            assert_eq!(event.time_raw, time_raw);
            assert_eq!(event.category, category);
            assert_eq!((event.month, event.day), (8, 31));
        }
        // 每条事件的 lineText 必须是对应原始行本身。
        for event in &timeline.events {
            let original = SYNTH_FULL_FLOW
                .split("\r\n")
                .nth(event.line_no - 1)
                .expect("line exists");
            assert_eq!(event.line_text, original);
        }
        assert_eq!(timeline.events[2].category_hits, vec![parser::Category::Complete]);
        assert_eq!(
            timeline.events[3].category_hits,
            vec![parser::Category::Launch],
            "Show QQ Window 只命中 launch"
        );
        assert_eq!(
            (timeline.events[0].hour, timeline.events[0].minute, timeline.events[0].second),
            (18, 0, 25)
        );
    }

    #[test]
    fn sample_missing_complete_has_no_complete_event() {
        let timeline = parse_sample(SYNTH_MISSING_COMPLETE.as_bytes());
        assert_eq!(timeline.line_count, 5);
        assert_eq!(timeline.events.len(), 4);
        assert_eq!(timeline.unparsed_line_count, 1);
        assert!(
            timeline
                .events
                .iter()
                .all(|event| event.category != parser::Category::Complete),
            "缺完成标记时不得凭空产生 complete 事件"
        );
        let expected = [(1, "0912/101500"), (2, "0912/101659"), (3, "0912/101700"), (4, "0912/101701")];
        for (event, (line_no, time_raw)) in timeline.events.iter().zip(expected) {
            assert_eq!(event.line_no, line_no);
            assert_eq!(event.time_raw, time_raw);
        }
        assert_eq!(timeline.events[2].category, parser::Category::Launch);
        assert!(timeline
            .limitations
            .iter()
            .any(|note| note.contains("1 行无时间戳")));
    }

    #[test]
    fn sample_garbled_bytes_do_not_disturb_other_lines() {
        let bytes = synth_garbled();
        let timeline = parse_sample(&bytes);
        assert_eq!(timeline.encoding, parser::DecodePath::Lossy);
        assert_eq!(timeline.line_count, 4);
        assert_eq!(timeline.unparsed_line_count, 1, "只有乱码行没有时间片段");
        assert_eq!(timeline.events.len(), 3);

        // 第 1 行：ASCII 安装行不受后续坏字节影响，行号与分类都正确。
        assert_eq!(timeline.events[0].line_no, 1);
        assert_eq!(timeline.events[0].category, parser::Category::Install);
        assert_eq!(timeline.events[0].line_text, "0913/090000 SETUP start");

        // 第 2 行：GBK 字节在降级路径下不可恢复，但该行仍产出事件（不丢行）。
        assert_eq!(timeline.events[1].line_no, 2);
        assert_eq!(timeline.events[1].category, parser::Category::Other);
        assert!(timeline.events[1].line_text.contains('\u{fffd}'));

        // 第 4 行：越界值原样保留并记入 limitations。
        assert_eq!(timeline.events[2].line_no, 4);
        assert_eq!(timeline.events[2].time_raw, "1332/256199");
        assert_eq!((timeline.events[2].month, timeline.events[2].day), (13, 32));
        assert_eq!(
            (
                timeline.events[2].hour,
                timeline.events[2].minute,
                timeline.events[2].second
            ),
            (25, 61, 99)
        );
        assert!(timeline
            .limitations
            .iter()
            .any(|note| note.contains("1332/256199") && note.contains("越界")));
        assert!(timeline
            .limitations
            .iter()
            .any(|note| note.contains("U+FFFD")));
    }

    #[test]
    fn pure_gbk_sample_decodes_chinese_and_classifies() {
        // 整份文件都是 GBK：走 GBK 分支，中文关键字可正常解码与分类。
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"0831/180025 \xBF\xAA\xCA\xBC\xB0\xB2\xD7\xB0\r\n"); // 开始安装
        bytes.extend_from_slice(b"0831/180708 \xB0\xB2\xD7\xB0\xCD\xEA\xB3\xC9\r\n"); // 安装完成
        let timeline = parse_sample(&bytes);
        assert_eq!(timeline.encoding, parser::DecodePath::Gbk);
        assert_eq!(timeline.line_count, 2);
        assert_eq!(timeline.events[0].line_text, "0831/180025 开始安装");
        assert_eq!(timeline.events[0].category, parser::Category::Install);
        assert_eq!(timeline.events[1].line_text, "0831/180708 安装完成");
        assert_eq!(timeline.events[1].category, parser::Category::Complete);
    }

    #[test]
    fn empty_sample_is_zero_events() {
        let timeline = parse_sample(b"");
        assert_eq!(timeline.line_count, 0);
        assert_eq!(timeline.events.len(), 0);
        assert_eq!(timeline.unparsed_line_count, 0);
        assert_eq!(timeline.encoding, parser::DecodePath::Utf8);
    }

    #[test]
    fn every_event_carries_a_usable_source_ref() {
        let timeline = parse_sample(SYNTH_FULL_FLOW.as_bytes());
        let base = "qq_setup.log";
        let refs: Vec<String> = timeline
            .events
            .iter()
            .map(|event| format!("{base}#L{}", event.line_no))
            .collect();
        assert_eq!(
            refs,
            vec![
                "qq_setup.log#L1",
                "qq_setup.log#L2",
                "qq_setup.log#L3",
                "qq_setup.log#L4",
                "qq_setup.log#L5",
            ]
        );
    }

    #[test]
    fn result_nodes_declare_required_columns() {
        let timeline = parse_sample(SYNTH_FULL_FLOW.as_bytes());
        let nodes = result_nodes(&timeline);
        assert_eq!(nodes.len(), 2);
        let keys: Vec<&str> = nodes[1].columns.iter().map(|column| column.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "qqsetup.line_no",
                "qqsetup.time_raw",
                "qqsetup.month",
                "qqsetup.day",
                "qqsetup.hour",
                "qqsetup.minute",
                "qqsetup.second",
                "qqsetup.category",
                "qqsetup.line_text",
                "qqsetup.source_ref",
            ]
        );
        let empty = result_nodes(&parse_sample(b""));
        assert_eq!(empty.len(), 1, "空日志只保留文件级汇总节点");
    }

    #[test]
    fn oversized_input_is_reported_not_truncated() {
        let error = parser::parse(&vec![b'0'; parser::MAX_INPUT_BYTES + 1], "qq_setup.log")
            .expect_err("cap exceeded");
        assert!(error.contains("超过上限"));
    }
}
