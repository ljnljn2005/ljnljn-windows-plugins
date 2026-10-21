//! 便笺 CSV 凭据候选抽取引擎。
//!
//! 逐行逐列扫描单元格文本，按不区分大小写的键名 `VCpwd` 匹配
//! `VCpwd: 值` / `VCpwd=值` / `VCpwd：值`（兼容中文冒号），对值做**原样**
//! 输出（只去首尾空白与外层成对引号，不做长度或字符集合法性过滤），
//! 再按值去重并统计出现次数。
//!
//! 本模块不触碰宿主与 I/O：输入是字节，输出是纯数据结构，便于单元测试；
//! 宿主句柄读取在 `crate::lib` 的 analyzer 里完成。

use std::collections::HashMap;

use crate::charset;
use crate::csv;

/// 原始单元格文本的截断长度（字符数）。
pub const RAW_CELL_LIMIT: usize = 200;
/// 同一文件的最大凭据值个数，超过时截断并记入 limitations。
pub const MAX_CREDENTIALS: usize = 2000;
/// 每个凭据值最多保留的其余出现位置条数。
pub const MAX_OCCURRENCES: usize = 50;
/// 输入字节硬上限（与宿主读取 CAP 一致）。
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// 键名（ASCII 不区分大小写）。
pub const KEY_TOKEN: &str = "vcpwd";
/// 允许的键值分隔符：ASCII 冒号、等号与中文冒号。
const SEPARATORS: [char; 3] = [':', '=', '：'];

/// 列标识：有表头时为表头单元格原文，否则为 0 起的列序号。
#[derive(Clone, Debug, PartialEq)]
pub enum ColumnRef {
    Named(String),
    Index(usize),
}

impl ColumnRef {
    /// 输出字段 `columnNameOrIndex` 的字符串形式。
    pub fn label(&self) -> String {
        match self {
            Self::Named(name) => name.clone(),
            Self::Index(index) => index.to_string(),
        }
    }
}

/// 同一凭据值的一次出现位置。
#[derive(Clone, Debug, PartialEq)]
pub struct Occurrence {
    pub row_index: usize,
    pub column: ColumnRef,
    /// 该出现处单元格内、值之后还有几个键值对。
    pub trailing_pairs: usize,
}

/// 一个去重后的凭据值。
#[derive(Clone, Debug, PartialEq)]
pub struct Credential {
    /// 输出字段 `value`：原样凭据值。
    pub value: String,
    /// 输出字段 `rawCell`：首次出现处的原始单元格文本（截断到 [`RAW_CELL_LIMIT`]）。
    pub raw_cell: String,
    /// 输出字段 `rowIndex`：首次出现的逻辑行号（从 1 开始，含表头）。
    pub row_index: usize,
    /// 输出字段 `columnNameOrIndex`。
    pub column: ColumnRef,
    /// 输出字段 `truncated`：首次出现处的原始单元格文本是否被截断。
    pub truncated: bool,
    /// 按值去重后的出现次数。
    pub occurrences: usize,
    /// 首次出现处的单元格内、值之后还有几个键值对。
    pub trailing_pairs: usize,
    /// 其余出现位置（最多 [`MAX_OCCURRENCES`] 条）。
    pub occurrence_locations: Vec<Occurrence>,
    /// 首次出现处的行尾是否为 CRLF。
    pub crlf_row: bool,
}

impl Credential {
    /// 供结果属性使用的列标识字符串。
    pub fn column_label(&self) -> String {
        self.column.label()
    }
}

/// 单文件分析报告，覆盖需求里的全部输出字段。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct FileReport {
    /// 输出字段 `sourceFile`：宿主提供的显示名（不是检材真实路径）。
    pub source_file: String,
    /// 输出字段 `encoding`。
    pub encoding: String,
    /// 输出字段 `delimiter`（`,` 或制表符）。
    pub delimiter: String,
    /// 输出字段 `recordCount`：非空逻辑记录数（含表头）。
    pub record_count: usize,
    /// 输出字段 `credentialCount`：按值去重后的凭据个数。
    pub credential_count: usize,
    /// 输出字段 `unparsedRowCount`。
    pub unparsed_row_count: usize,
    /// 是否判定为含表头（决定 `columnNameOrIndex` 的取值形式）。
    pub has_header: bool,
    /// 输出字段 `credentials`。
    pub credentials: Vec<Credential>,
    /// 输出字段 `limitations`。
    pub limitations: Vec<String>,
    /// 值整体被单/双引号包裹的命中个数（保留原样，只提示）。
    pub quoted_values: usize,
    /// 值内含 ASCII 冒号或中文冒号的命中个数（只提示）。
    pub colon_values: usize,
    /// 值内含逗号的命中个数（只提示）。
    pub comma_values: usize,
}

/// 在字符串中找下一个 VCpwd 键名（ASCII 不区分大小写）。
fn find_key(text: &str, from: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let needle = KEY_TOKEN.as_bytes();
    if from >= bytes.len() {
        return None;
    }
    (from..bytes.len()).find(|index| {
        *index + needle.len() <= bytes.len()
            && text.is_char_boundary(*index)
            && bytes[*index..*index + needle.len()].eq_ignore_ascii_case(needle)
    })
}

/// 键名之后（跳过空白）紧跟的分隔符位置。
fn separator_after(text: &str, key_end: usize) -> Option<usize> {
    let rest = &text[key_end..];
    let trimmed = rest.trim_start();
    let character = trimmed.chars().next()?;
    if SEPARATORS.contains(&character) {
        Some(key_end + (rest.len() - trimmed.len()))
    } else {
        None
    }
}

/// 单元格文本压平成便笺文本：CRLF / CR 统一为 LF。
fn flatten(raw: &str) -> String {
    raw.replace("\r\n", "\n").replace('\r', "\n")
}

/// 值的结束位置：值从 `value_start` 开始，在首个"独立空白 + 新键值对"处结束。
///
/// 判定只用递归的 `key:value` / `key=value` 结构，保证可预测：
///
/// * `a:b`、`10:01:00`、`a,b`、`he said ""hi""` 这类非键值对文本原样保留；
/// * 单元格内多组键值对时（`VCpwd: secret 账号=aaa`、`x=1 VCpwd: abc y=2`），
///   从首个键值对的值开始找下一个紧随空白的键值对，值在其前的空白处结束，
///   由调用方把后续键值对当作独立词继续扫描；
/// * 引号包裹的值止于闭合引号。
fn value_boundary(text: &str, value_start: usize) -> usize {
    let bytes = text.as_bytes();
    // 跳过值前的空白：这些空白不属于值，也不参与「空白 + 新键值对」判定。
    let mut index = value_start;
    while index < bytes.len() && matches!(bytes[index], b' ' | b'\t') {
        index += 1;
    }
    // 值以引号包裹时：止于闭合引号，内部一律原样保留。
    if index < bytes.len() && bytes[index] == b'"' {
        return match text[index + 1..].find('"') {
            Some(close) => index + 1 + close + 1,
            None => text.len(),
        };
    }
    while index < bytes.len() {
        if matches!(bytes[index], b' ' | b'\t') {
            let mut probe = index + 1;
            while probe < bytes.len() && matches!(bytes[probe], b' ' | b'\t') {
                probe += 1;
            }
            if probe < bytes.len() && is_pair_at(text, probe) {
                return index;
            }
        }
        index += 1;
    }
    text.len()
}

/// `index` 处是否是一个新的 `key:value` / `key=value` 键值对的开头。
///
/// 键名是英文短标识符或一个中文词（到冒号/等号为止），右侧必须非空。
fn is_pair_at(text: &str, index: usize) -> bool {
    let rest = &text[index..];
    // 逐个字符收集键名：遇到分隔符/空白即停止（不能用字节 `find`，中文键名
    // 的 UTF-8 首字节可能等于 ASCII `:`/`=`）。
    let mut key_len = 0;
    for character in rest.chars() {
        if matches!(character, ':' | '=' | '：' | ' ' | '\t' | '\n' | '\r') {
            break;
        }
        key_len += character.len_utf8();
        if key_len > 32 {
            return false;
        }
    }
    if key_len == 0 {
        return false;
    }
    let head = &rest[..key_len];
    let Some(separator) = rest[key_len..].chars().next() else {
        return false;
    };
    if !matches!(separator, ':' | '=' | '：') {
        return false;
    }
    let ascii_key = head
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        && head
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic());
    let chinese_key = !ascii_key
        && head
            .chars()
            .next()
            .is_some_and(|character| !character.is_ascii() && !character.is_whitespace());
    if !(ascii_key || chinese_key) {
        return false;
    }
    let tail = rest[key_len + separator.len_utf8()..].trim_start_matches([' ', '\t']);
    !tail.is_empty() && !tail.starts_with([':', '=', '：'])
}
/// 取值：跳过分隔符后的空白；以成对引号包裹时取引号内内容；再去首尾空白。
/// 值本身不做长度或字符集过滤。
fn materialize_value(tail: &str) -> (String, usize) {
    let trimmed = tail.trim_start();
    let leading = tail.len() - trimmed.len();
    for quote in ['"', '\''] {
        if let Some(rest) = trimmed.strip_prefix(quote) {
            if let Some(close) = rest.find(quote) {
                return (rest[..close].to_owned(), leading);
            }
        }
    }
    (trimmed.trim_end().to_owned(), leading)
}

/// 单单元格抽取：返回 (值, 值在单元格内的字节偏移, 值之后的键值对个数)。
fn cell_values(text: &str) -> Vec<(String, usize, usize)> {
    let mut found = Vec::new();
    let mut cursor = 0;
    while let Some(position) = find_key(text, cursor) {
        let key_end = position + KEY_TOKEN.len();
        let Some(separator) = separator_after(text, key_end) else {
            cursor = key_end;
            continue;
        };
        let separator_len = text[separator..].chars().next().map_or(1, char::len_utf8);
        let value_start = separator + separator_len;
        let end = value_boundary(text, value_start);
        let segment = &text[value_start..end];
        let (value, leading) = materialize_value(segment);
        // 值之后可能还有 key=value；它们属于同一个单元格，但不在值本身里。
        let trailing = trailing_pairs(&text[end..]);
        found.push((value, value_start + leading, trailing));
        cursor = end.max(key_end);
    }
    found
}

/// 值之后还有几个 `key:value` / `key=value` 键值对（按空白切词后逐个判定）。
fn trailing_pairs(segment: &str) -> usize {
    segment
        .split([' ', '\t', '\n'])
        .filter(|word| !word.is_empty())
        .filter(|word| is_pair_at(word, 0))
        .count()
}

/// 统计一段文本里 VCpwd 键值对的个数。
#[cfg(test)]
#[allow(dead_code)] // Kept from the v1 parser; the v2 harness exercises extraction directly.
fn count_pairs(text: &str) -> usize {
    let mut count = 0;
    let mut cursor = 0;
    while let Some(position) = find_key(text, cursor) {
        let key_end = position + KEY_TOKEN.len();
        match separator_after(text, key_end) {
            Some(separator) => {
                let len = text[separator..].chars().next().map_or(1, char::len_utf8);
                count += 1;
                cursor = separator + len;
            }
            None => cursor = key_end,
        }
    }
    count
}
/// 截断原始单元格文本到 [`RAW_CELL_LIMIT`] 字符。
fn truncate_cell(text: &str) -> (String, bool) {
    match text.char_indices().nth(RAW_CELL_LIMIT) {
        Some((cut, _)) => (text[..cut].to_owned(), true),
        None => (text.to_owned(), false),
    }
}

/// 值整体被同一种引号包裹（首尾都是单引号或都是双引号）。
fn is_quoted(value: &str) -> bool {
    let chars: Vec<char> = value.chars().collect();
    chars.len() >= 2 && matches!(chars[0], '"' | '\'') && chars[0] == chars[chars.len() - 1]
}

fn preview_list(items: &[usize]) -> String {
    let preview: Vec<String> = items.iter().take(10).map(|item| item.to_string()).collect();
    if items.len() > preview.len() {
        format!("{} 等", preview.join(","))
    } else {
        preview.join(",")
    }
}

fn column_reference(header: Option<&[String]>, column: usize) -> ColumnRef {
    match header.and_then(|cells| cells.get(column)) {
        Some(name) if !name.trim().is_empty() => ColumnRef::Named(name.trim().to_owned()),
        _ => ColumnRef::Index(column),
    }
}

fn is_binary_container(bytes: &[u8]) -> bool {
    bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(&[0xD0, 0xCF, 0x11, 0xE0])
}

/// 表头中只有 `VCpwd` 字样（没有分隔符）的单元格个数。
fn bare_key_cells(header: Option<&[String]>) -> usize {
    header.map_or(0, |cells| {
        cells
            .iter()
            .filter(|cell| cell.trim().eq_ignore_ascii_case(KEY_TOKEN))
            .count()
    })
}

/// 固定写入每条结果的未覆盖范围说明：不允许把未做的事说成已做。
pub fn static_limitations() -> Vec<String> {
    vec![
        "未覆盖：不实现 VeraCrypt 解密挂载，不调用任何外部程序或驱动".to_owned(),
        "未覆盖：不校验 VCpwd 值是否为正确密码，不统计卷内文件数量与文档类型".to_owned(),
        "未覆盖：不跨文件合并凭据；多文件需分别对每个文件调用本分析器".to_owned(),
        "不硬编码任何案件取值：凭据值只来自本次检材字节".to_owned(),
    ]
}

/// 解析输入字节，产出完整文件报告（纯函数，不做 I/O）。
pub fn analyze_bytes(source_file: &str, bytes: &[u8]) -> FileReport {
    let decoded = charset::decode(bytes);
    let mut report = FileReport {
        source_file: source_file.to_owned(),
        encoding: decoded.encoding.clone(),
        ..FileReport::default()
    };
    let mut limitations = Vec::new();

    if decoded.replacement_count > 0 {
        limitations.push(format!(
            "编码替换降级：{} 个非法字节序列被替换为 U+FFFD，该处内容可能不完整；已抽出的键值对仍原样输出",
            decoded.replacement_count
        ));
    }
    if decoded.nul_bytes > 0 && !decoded.encoding.starts_with("UTF-16") {
        limitations.push(format!(
            "非 UTF-16 编码中出现 {} 个 NUL 字节：文件可能不是纯文本 CSV 或已损坏",
            decoded.nul_bytes
        ));
    }
    if is_binary_container(bytes) {
        limitations.push(
            "文件头为 ZIP(PK) 或 OLE(D0CF11E0) 签名，疑为二进制容器而非文本 CSV；本插件不做二进制解包，结果不可信".to_owned(),
        );
    }
    if bytes.len() >= MAX_INPUT_BYTES {
        limitations.push(format!(
            "输入达到上限 {MAX_INPUT_BYTES} 字节，仅解析前 {MAX_INPUT_BYTES} 字节"
        ));
    }
    if decoded.encoding.ends_with("-LOSSY") {
        limitations.push(
            "编码判定含替换降级（UTF-8-LOSSY）：该文件既不是合法 UTF-8 也不是合法 GBK/GB18030，字符集不确定"
                .to_owned(),
        );
    }

    if decoded.text.is_empty() {
        limitations
            .push("文件为空（0 字节或只有 BOM）：recordCount=0、credentialCount=0".to_owned());
        limitations.push(csv::parse("").delimiter_basis);
        limitations.extend(static_limitations());
        report.limitations = limitations;
        return report;
    }

    let parsed = csv::parse(&decoded.text);
    let header_decision = csv::header_decision(&parsed.records);
    report.delimiter = parsed.delimiter.to_string();
    report.has_header = header_decision.has_header;
    report.record_count = parsed.records.len();
    limitations.push(parsed.delimiter_basis.clone());
    limitations.push(format!("表头判定：{}", header_decision.basis));
    if !parsed.structural_errors.is_empty() {
        limitations.push(format!(
            "{} 条记录存在 CSV 结构异常（引号未闭合/多余字符），记录号：{}",
            parsed.structural_errors.len(),
            preview_list(&parsed.structural_errors)
        ));
    }
    let width = parsed
        .records
        .first()
        .map_or(0, |record| record.fields.len());
    if !report.has_header && !parsed.records.is_empty() {
        limitations
            .push("无表头：首条记录按数据处理，columnNameOrIndex 输出 0 起的列序号".to_owned());
    }

    let header_cells: Option<&[String]> = if report.has_header {
        parsed
            .records
            .first()
            .map(|record| record.fields.as_slice())
    } else {
        None
    };
    let first_data = usize::from(report.has_header);

    let mut unparsed = parsed.structural_errors.len();
    let mut width_mismatch = 0_usize;
    let mut credentials: Vec<Credential> = Vec::new();
    let mut index_by_value: HashMap<String, usize> = HashMap::new();
    let mut dropped_pairs = 0_usize;

    for record in parsed.records.iter().skip(first_data) {
        let structural = !record.issues.is_empty();
        if record.fields.len() != width {
            if !structural {
                unparsed += 1;
            }
            width_mismatch += 1;
        }
        for (column, raw) in record.fields.iter().enumerate() {
            let text = flatten(raw);
            for (value, _, trailing_pairs) in cell_values(&text) {
                if value.contains(':') || value.contains('：') {
                    report.colon_values += 1;
                }
                if value.contains(',') {
                    report.comma_values += 1;
                }
                if is_quoted(&value) {
                    report.quoted_values += 1;
                }
                let column_ref = column_reference(header_cells, column);
                match index_by_value.get(&value).copied() {
                    Some(position) => {
                        let existing = &mut credentials[position];
                        existing.occurrences += 1;
                        if existing.occurrence_locations.len() < MAX_OCCURRENCES {
                            existing.occurrence_locations.push(Occurrence {
                                row_index: record.index,
                                column: column_ref,
                                trailing_pairs,
                            });
                        }
                    }
                    None if credentials.len() >= MAX_CREDENTIALS => dropped_pairs += 1,
                    None => {
                        let (cell, truncated) = truncate_cell(&text);
                        index_by_value.insert(value.clone(), credentials.len());
                        credentials.push(Credential {
                            value,
                            raw_cell: cell,
                            row_index: record.index,
                            column: column_ref,
                            truncated,
                            occurrences: 1,
                            trailing_pairs,
                            occurrence_locations: Vec::new(),
                            crlf_row: record.crlf,
                        });
                    }
                }
            }
        }
    }

    if dropped_pairs > 0 {
        limitations.push(format!(
            "凭据值数量超过上限 {MAX_CREDENTIALS}，{dropped_pairs} 次命中未输出；请拆分文件后重跑"
        ));
    }
    if width_mismatch > 0 {
        limitations.push(format!(
            "{width_mismatch} 条记录字段数与首条记录（{width} 列）不一致，计入 unparsedRowCount，不做补齐猜测"
        ));
    }
    if report.quoted_values > 0 {
        limitations.push(format!(
            "{} 个值整体被单/双引号包裹：按\"原样输出\"保留，使用前请人工确认是否应去掉引号",
            report.quoted_values
        ));
    }
    if report.colon_values > 0 {
        limitations.push(format!(
            "{} 个值内部含冒号（按\"原样输出\"保留，未做 key:value 二次切分）",
            report.colon_values
        ));
    }
    if credentials.iter().any(|item| item.crlf_row) {
        limitations
            .push("部分首次出现使用 CRLF 行尾；已统一按 CRLF/LF/CR 解析，行号不受影响".to_owned());
    }
    let bare = bare_key_cells(header_cells);
    if bare > 0 {
        limitations.push(format!(
            "{bare} 个表头单元格只有 VCpwd 字样（没有\": 值\"），本身不产生凭据；仅出现 VCpwd:值 形式时才提取"
        ));
    }
    if credentials.is_empty() && !limitations.iter().any(|item| item.contains("无表头")) {
        limitations
            .push("未发现符合 VCpwd:值 形式的单元格：credentialCount=0（不是解析失败）".to_owned());
    }
    limitations.extend(static_limitations());
    report.unparsed_row_count = unparsed;
    report.credential_count = credentials.len();
    report.credentials = credentials;
    report.limitations = limitations;
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(text: &str) -> FileReport {
        analyze_bytes("data.csv", text.as_bytes())
    }

    fn values(report: &FileReport) -> Vec<&str> {
        report
            .credentials
            .iter()
            .map(|item| item.value.as_str())
            .collect()
    }

    #[test]
    fn extracts_all_separators_and_case_insensitive_keys() {
        let report = report(
            "索引,内容\r\n1,VCpwd: abc\r\n2,备注\r\n3,vcpwd=xyz\r\n4,VCpwd：中文冒号\r\n5,VCPWD :  spacing  \r\n",
        );
        assert_eq!(report.encoding, "UTF-8");
        assert_eq!(report.delimiter, ",");
        assert!(report.has_header);
        assert_eq!(report.record_count, 6);
        assert_eq!(report.unparsed_row_count, 0);
        assert_eq!(values(&report), vec!["abc", "xyz", "中文冒号", "spacing"]);
        let abc = &report.credentials[0];
        assert_eq!(abc.row_index, 2);
        assert_eq!(abc.column_label(), "内容");
        assert_eq!(abc.raw_cell, "VCpwd: abc");
        assert!(!abc.truncated);
        assert_eq!(abc.occurrences, 1);
        assert_eq!(abc.trailing_pairs, 0);
    }

    #[test]
    fn deduplicates_and_counts_occurrences() {
        let report = report("内容\r\nVCpwd: dup\r\nVCpwd: dup\r\nVCpwd: other\r\n");
        assert_eq!(report.credential_count, 2);
        assert_eq!(report.credentials[0].value, "dup");
        assert_eq!(report.credentials[0].occurrences, 2);
        assert_eq!(report.credentials[0].row_index, 2);
        assert_eq!(report.credentials[0].occurrence_locations[0].row_index, 3);
        assert_eq!(report.credentials[1].occurrences, 1);
    }

    #[test]
    fn values_may_contain_colons_commas_quotes_and_inner_quotes() {
        let report = report(
            "备注\r\n\"VCpwd: a:b\"\r\n\"VCpwd: a,b\"\r\n\"VCpwd: 'q1'\"\r\n\"VCpwd: he said \"\"hi\"\"\"\r\nx,\"adr=10:01:00 VCpwd: a:b\"\r\n",
        );
        assert_eq!(values(&report), vec!["a:b", "a,b", "q1", "he said \"hi\""]);
        // 两条记录都命中了 a:b：按值去重计数。
        assert_eq!(report.credentials[0].occurrences, 2);
        assert_eq!(report.credentials[0].row_index, 2);
        assert_eq!(report.credentials[0].occurrence_locations[0].row_index, 6);
        assert_eq!(
            report.credentials[0].occurrence_locations[0].column.label(),
            "1"
        );
        // CSV 解析阶段已按 RFC 4180 去掉外层引号并还原 ""，值本身不再带引号；
        // 保留冒号提示即可，不再声称“值被引号包裹”。
        assert!(report
            .limitations
            .iter()
            .any(|item| item.contains("值内部含冒号")));
    }

    #[test]
    fn value_stops_at_next_key_value_pair_and_keeps_newlines() {
        let first = report("内容\r\nVCpwd: secret 账号=aaa\r\n");
        assert_eq!(first.credentials[0].value, "secret");
        assert_eq!(first.credentials[0].trailing_pairs, 1);

        let chained = report("内容\r\nx=1 VCpwd: abc y=2\r\n");
        assert_eq!(chained.credentials[0].value, "abc");
        assert_eq!(chained.credentials[0].trailing_pairs, 1);

        let wrapped = report("\"VCpwd: line1\nline2\"\r\n");
        assert_eq!(wrapped.credentials[0].value, "line1\nline2");

        let timed = report("时间,内容\r\n10:01:00,VCpwd: x\r\n");
        assert_eq!(timed.credentials[0].value, "x");
        assert_eq!(timed.credentials[0].column_label(), "内容");
    }

    #[test]
    fn long_cell_is_truncated_at_200_chars() {
        let filler = "字".repeat(300);
        let long_cell = analyze_bytes("data.csv", format!("\"VCpwd: x2\n{filler}\"\n").as_bytes());
        assert!(long_cell.credentials[0].truncated);
        assert_eq!(
            long_cell.credentials[0].raw_cell.chars().count(),
            RAW_CELL_LIMIT
        );
        assert!(long_cell.credentials[0].value.starts_with("x2"));
    }

    #[test]
    fn empty_and_bom_only_files_have_zero_credentials() {
        let empty = analyze_bytes("data.csv", b"");
        assert_eq!(empty.record_count, 0);
        assert_eq!(empty.credential_count, 0);
        assert_eq!(empty.unparsed_row_count, 0);
        assert!(empty
            .limitations
            .iter()
            .any(|item| item.contains("文件为空")));

        let bom_only = analyze_bytes("data.csv", b"\xEF\xBB\xBF");
        assert_eq!(bom_only.record_count, 0);
        assert_eq!(bom_only.credential_count, 0);
    }

    #[test]
    fn no_hit_file_reports_zero_credentials() {
        let report = report("序号,内容\r\n1,今天开会\r\n2,改天再约\r\n");
        assert_eq!(report.credential_count, 0);
        assert_eq!(report.record_count, 3);
        assert_eq!(report.unparsed_row_count, 0);
        assert!(report
            .limitations
            .iter()
            .any(|item| item.contains("未发现符合")));
    }

    #[test]
    fn inconsistent_rows_count_as_unparsed() {
        let report = report("a,b\r\n1,VCpwd: x\r\nonly-one\r\n");
        assert_eq!(report.unparsed_row_count, 1);
        assert_eq!(report.credentials[0].column_label(), "b");
        assert!(report
            .limitations
            .iter()
            .any(|item| item.contains("字段数与首条记录")));
    }

    #[test]
    fn headerless_file_uses_column_index() {
        let report = report("VCpwd: first\r\nsecond,VCpwd: second\r\n");
        assert!(!report.has_header);
        assert_eq!(report.credentials[0].column_label(), "0");
        assert_eq!(report.credentials[0].row_index, 1);
    }

    #[test]
    fn gbk_input_is_decoded_and_binary_container_is_flagged() {
        let (gbk, _, _) = encoding_rs::GBK.encode("索引,内容\r\n1,VCpwd: 金色眼睛\r\n");
        let report = analyze_bytes("data.csv", gbk.as_ref());
        assert_eq!(report.encoding, "GBK");
        assert_eq!(report.credentials[0].value, "金色眼睛");

        let mut zip = b"PK\x03\x04".to_vec();
        zip.extend_from_slice(b"VCpwd: inside-zip\n");
        let report = analyze_bytes("data.csv", &zip);
        assert!(report
            .limitations
            .iter()
            .any(|item| item.contains("二进制容器")));
    }

    #[test]
    fn duplicate_header_names_are_reported_verbatim() {
        let single = report("内容,内容\r\n1,VCpwd: x\r\n");
        assert_eq!(single.credentials[0].column_label(), "内容");

        let second = report("VCpwd: y,VCpwd: z\n");
        assert!(!second.has_header);
        assert_eq!(second.credentials[0].column_label(), "0");
        assert_eq!(second.credentials[1].column_label(), "1");
        assert_eq!(second.credentials[1].row_index, 1);

        let duplicate = report("内容,内容\r\nVCpwd: y,VCpwd: z\r\n");
        assert!(duplicate.has_header);
        assert_eq!(duplicate.credentials[0].column_label(), "内容");
        assert_eq!(duplicate.credentials[1].column_label(), "内容");
        assert_eq!(duplicate.credentials[1].row_index, 2);
    }

    #[test]
    fn bare_key_cell_is_reported_but_not_extracted() {
        let report = report("索引,VCpwd\r\n1,VCpwd: abc\r\n");
        assert!(report.has_header);
        assert_eq!(values(&report), vec!["abc"]);
        assert_eq!(report.credentials[0].column_label(), "VCpwd");
        assert_eq!(report.credentials[0].row_index, 2);
        assert!(report
            .limitations
            .iter()
            .any(|item| item.contains("只有 VCpwd 字样")));
    }

    #[test]
    fn value_offsets_are_char_boundary_safe() {
        let report = report("内容\r\n\"VCpwd：中文 密码=x\"\r\n");
        assert_eq!(report.credentials[0].value, "中文");
        assert_eq!(report.credentials[0].trailing_pairs, 1);
        assert_eq!(report.credentials[0].raw_cell, "VCpwd：中文 密码=x");
    }
}
