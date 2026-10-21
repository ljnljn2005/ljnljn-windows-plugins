//! 标准 CSV 引号规则解析（RFC 4180 风格）与分隔符 / 表头判定。
//!
//! 约定：
//! * 引号字段以 `"` 开始，字段内的 `""` 表示一个 `"`；
//! * 引号字段内允许分隔符、CR、LF 与其它任意字符；
//! * 行尾识别 CRLF / LF / CR 三种；
//! * `rowIndex` 是**逻辑记录号，从 1 开始**（含表头）；引号字段跨物理行时，
//!   下一条记录仍只算一行，并记录该记录覆盖的物理行区间；
//! * "空记录"＝文件里确实没有内容的空行，或只有分隔符、所有字段都是空白的行
//!   （例如 Excel 导出尾部多余的 `,,,`），不计入 recordCount。

use std::collections::BTreeMap;

/// 一条逻辑记录的解析结果。
#[derive(Clone, Debug, PartialEq)]
pub struct Record {
    /// 逻辑记录号（从 1 开始，含表头）。
    pub index: usize,
    /// 记录起始物理行（从 1 开始）。
    pub physical_line: usize,
    /// 记录结束物理行（引号字段跨行时大于 [`Record::physical_line`]）。
    pub physical_line_end: usize,
    pub fields: Vec<String>,
    /// 记录以 CRLF / 单独 CR 结束。
    pub crlf: bool,
    /// 结构性异常说明（引号未闭合、引号闭合后又出现引号、字段数超限等）。
    pub issues: Vec<String>,
}

impl Record {
    /// 该记录是否为空记录（不计入 recordCount）。
    pub fn is_blank(&self) -> bool {
        self.issues.is_empty() && self.fields.iter().all(|field| field.trim().is_empty())
    }
}

/// 一次解析的整体结果。
#[derive(Clone, Debug, PartialEq)]
pub struct ParsedText {
    /// 采用的字段分隔符（`,` 或 `\t`）。
    pub delimiter: char,
    /// 分隔符判定依据的文字说明，写入 limitations 便于复核。
    pub delimiter_basis: String,
    pub records: Vec<Record>,
    /// 存在结构性异常的记录号。
    pub structural_errors: Vec<usize>,
    /// 出现过 CRLF 或单独 CR 行尾。
    pub saw_crlf: bool,
}

/// 引号字段未闭合之前累积的单条记录上下文。
struct RawRecord {
    fields: Vec<String>,
    start_line: usize,
    end_line: usize,
    crlf: bool,
    issues: Vec<String>,
}

/// 单条记录字段数上限，防止畸形输入撑爆内存。
const MAX_FIELDS_PER_RECORD: usize = 4096;
/// 逻辑记录数上限。
const MAX_RECORDS: usize = 200_000;

/// 按给定分隔符扫描文本（引号规则与分隔符无关）。
fn scan(text: &str, delimiter: char) -> (Vec<RawRecord>, bool) {
    let mut records = Vec::new();
    let mut field = String::new();
    let mut fields: Vec<String> = Vec::new();
    let mut issues: Vec<String> = Vec::new();
    let mut overflowed = false;
    let mut in_quotes = false;
    let mut field_started = false;
    let mut line = 1_usize;
    let mut start_line = 1_usize;
    let mut saw_crlf = false;

    let mut chars = text.chars().peekable();
    while let Some(character) = chars.next() {
        if in_quotes {
            match character {
                '"' => {
                    if chars.peek() == Some(&'"') {
                        chars.next();
                        field.push('"');
                    } else {
                        in_quotes = false;
                    }
                }
                _ => {
                    if character == '\n' {
                        line += 1;
                    }
                    field.push(character);
                }
            }
            continue;
        }
        match character {
            '"' if !field_started => {
                in_quotes = true;
                field_started = true;
            }
            '"' => {
                // 引号闭合后（或非引号字段开头）出现的引号：按字面保留并记结构性异常。
                issues.push(format!("引号字段闭合后又出现引号（物理行 {line}）"));
                field.push('"');
                field_started = true;
            }
            character if character == delimiter => {
                if fields.len() < MAX_FIELDS_PER_RECORD {
                    fields.push(std::mem::take(&mut field));
                } else {
                    overflowed = true;
                    field.clear();
                }
                field_started = false;
            }
            '\r' | '\n' => {
                let mut width = 1;
                if character == '\r' && chars.peek() == Some(&'\n') {
                    chars.next();
                    width = 2;
                } else if character == '\n' && chars.peek() == Some(&'\r') {
                    chars.next();
                    width = 2;
                }
                let crlf = width == 2 || character == '\r';
                if crlf {
                    saw_crlf = true;
                }
                if overflowed {
                    issues.push(format!("字段数超过 {MAX_FIELDS_PER_RECORD}"));
                }
                fields.push(std::mem::take(&mut field));
                records.push(RawRecord {
                    fields: std::mem::take(&mut fields),
                    start_line,
                    end_line: line,
                    crlf,
                    issues: std::mem::take(&mut issues),
                });
                overflowed = false;
                line += 1;
                start_line = line;
                field_started = false;
                if records.len() >= MAX_RECORDS {
                    return (records, saw_crlf);
                }
            }
            _ => {
                field.push(character);
                field_started = true;
            }
        }
    }
    if in_quotes {
        issues.push("文件结束时引号字段仍未闭合".to_owned());
    }
    if field_started || !field.is_empty() || !fields.is_empty() || !issues.is_empty() {
        if overflowed {
            issues.push(format!("字段数超过 {MAX_FIELDS_PER_RECORD}"));
        }
        fields.push(field);
        records.push(RawRecord {
            fields,
            start_line,
            end_line: line,
            crlf: false,
            issues,
        });
    }
    (records, saw_crlf)
}

/// 只包含分隔符与行尾的物理行（没有引号、没有内容）。
fn is_separator_only(record: &RawRecord) -> bool {
    record.issues.is_empty() && record.fields.iter().all(|field| field.trim().is_empty())
}

/// 统计字段数众数：`(众数字段数, 采用众数的记录数, 参与统计的记录数)`。
fn mode_shape(records: &[RawRecord]) -> (usize, usize, usize) {
    let mut histogram: BTreeMap<usize, usize> = BTreeMap::new();
    let mut total = 0;
    for record in records.iter().filter(|record| !is_separator_only(record)) {
        // 键用 fields - 1，避免单字段记录（1 列）与"无记录"混淆。
        *histogram
            .entry(record.fields.len().saturating_sub(1))
            .or_default() += 1;
        total += 1;
    }
    match histogram
        .into_iter()
        .max_by(|left, right| left.1.cmp(&right.1).then(right.0.cmp(&left.0)))
    {
        Some((fields, count)) => (fields + 1, count, total),
        None => (0, 0, 0),
    }
}

/// 分隔符判定的结果。
pub struct DelimiterChoice {
    pub delimiter: char,
    pub basis: String,
}

/// 按"字段数一致性"挑选分隔符：优先字段数众数覆盖的记录更多者，
/// 其次众数更大（列更多）者，二者都相同时按逗号。
pub fn choose_delimiter(text: &str) -> DelimiterChoice {
    let comma = mode_shape(&scan(text, ',').0);
    let tab = mode_shape(&scan(text, '\t').0);
    // 只有制表符能形成更多列，或在都形成多列时覆盖更多记录，才改选制表符。
    // 两个候选都只有 1 列时默认逗号：单列 CSV 很常见，不能因为制表符把所有行
    // 都算作“一致”就误判（这会把一整行带逗号的单元格错误合并）。
    let prefer_tab = tab.0 > comma.0 || (tab.0 == comma.0 && tab.0 > 1 && tab.1 > comma.1);
    let (delimiter, chosen, other, symbol) = if prefer_tab {
        ('\t', tab, comma, "制表符")
    } else {
        (',', comma, tab, "逗号")
    };
    let basis = if chosen.2 == 0 {
        "无可解析的物理记录，按默认逗号处理".to_owned()
    } else if chosen.0 <= 1 {
        format!(
            "逗号与制表符都未形成稳定的多列结构（逗号众数 {} 列、制表符众数 {} 列），按默认逗号处理",
            comma.0, tab.0
        )
    } else {
        format!(
            "按字段数一致性判定分隔符为{symbol}：众数 {} 列覆盖 {}/{} 条记录（另一候选 {} 列，覆盖 {}/{}）",
            chosen.0, chosen.1, chosen.2, other.0, other.1, other.2
        )
    };
    DelimiterChoice { delimiter, basis }
}

/// 解析文本：先定分隔符，再产出带逻辑行号与物理行区间的非空记录。
pub fn parse(text: &str) -> ParsedText {
    let choice = choose_delimiter(text);
    let (raw, saw_crlf) = scan(text, choice.delimiter);
    let mut structural_errors = Vec::new();
    let mut records = Vec::with_capacity(raw.len());
    for (position, record) in raw.into_iter().enumerate() {
        let index = position + 1;
        let parsed = Record {
            index,
            physical_line: record.start_line,
            physical_line_end: record.end_line,
            crlf: record.crlf,
            issues: record.issues,
            fields: record.fields,
        };
        if parsed.is_blank() {
            continue;
        }
        if !parsed.issues.is_empty() {
            structural_errors.push(index);
        }
        records.push(parsed);
    }
    ParsedText {
        delimiter: choice.delimiter,
        delimiter_basis: choice.basis,
        records,
        structural_errors,
        saw_crlf,
    }
}

/// 首条记录是否像无表头数据：任一单元格以 `VCpwd` 紧跟分隔符（`:`/`=`/`：`）
/// 开头。
fn first_record_is_data(record: &Record) -> bool {
    let key = "vcpwd";
    record.fields.iter().any(|field| {
        let trimmed = field.trim_start().trim_start_matches('"').trim_start();
        trimmed.len() > key.len()
            && trimmed.as_bytes()[..key.len()].eq_ignore_ascii_case(key.as_bytes())
            && matches!(trimmed.as_bytes()[key.len()], b':' | b'=' | 0xEF)
    })
}

/// 表头判定依据。
#[derive(Clone, Debug, PartialEq)]
pub struct HeaderDecision {
    pub has_header: bool,
    pub basis: String,
}

/// 判定是否有表头：首条记录有单元格以 `VCpwd` 开头（说明首条就是数据）时按
/// "无表头"处理；另外当首条记录中恰有单元格**只有** `VCpwd` 而数据行该列都是
/// `VCpwd: 值` 时，也判为表头（避免表头丢失列名）。
pub fn header_decision(records: &[Record]) -> HeaderDecision {
    let Some(first) = records.first() else {
        return HeaderDecision {
            has_header: false,
            basis: "无记录，不存在表头".to_owned(),
        };
    };
    if first_record_is_data(first) {
        return HeaderDecision {
            has_header: false,
            basis: "首条记录含形如 VCpwd 开头的单元格，按无表头处理".to_owned(),
        };
    }
    let bare_key = first
        .fields
        .iter()
        .position(|field| field.trim().eq_ignore_ascii_case("vcpwd"));
    if records.len() >= 2 {
        if let Some(column) = bare_key {
            let looks_like_header = records[1..].iter().all(|record| {
                record.fields.get(column).map_or(true, |field| {
                    let trimmed = field.trim();
                    !trimmed.eq_ignore_ascii_case("vcpwd")
                })
            });
            if looks_like_header {
                return HeaderDecision {
                    has_header: true,
                    basis: "首条记录含只有 VCpwd 的单元格且后续记录该列均为键值文本，判为表头"
                        .to_owned(),
                };
            }
            return HeaderDecision {
                has_header: false,
                basis: "首条记录含只有 VCpwd 的单元格，但数据行该列也为同样的字面值，按无表头处理"
                    .to_owned(),
            };
        }
    }
    HeaderDecision {
        has_header: true,
        basis: "首条记录作为表头".to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_escape_and_embedded_delimiters_and_newlines() {
        let text = "a,b\r\n\"x,y\",\"he said \"\"hi\"\"\"\r\n\"line1\nline2\",z\r\n";
        let parsed = parse(text);
        assert_eq!(parsed.delimiter, ',');
        assert!(parsed.saw_crlf);
        assert_eq!(parsed.records.len(), 3);
        assert_eq!(parsed.records[1].fields, vec!["x,y", "he said \"hi\""]);
        assert_eq!(parsed.records[2].fields, vec!["line1\nline2", "z"]);
        assert_eq!(parsed.records[2].index, 3);
        assert_eq!(parsed.records[2].physical_line, 3);
        assert_eq!(parsed.records[2].physical_line_end, 4);
        assert!(parsed.records[1].crlf);
        assert!(parsed.structural_errors.is_empty());
    }

    #[test]
    fn lf_and_cr_only_line_endings() {
        let parsed = parse("a,b\n1,2\n");
        assert_eq!(parsed.records.len(), 2);
        assert!(!parsed.saw_crlf);
        let parsed = parse("a,b\r1,2");
        assert_eq!(parsed.records.len(), 2);
        assert_eq!(parsed.records[1].fields, vec!["1", "2"]);
        assert!(parsed.saw_crlf);
        assert!(!parsed.records[1].crlf, "末条记录没有行尾");
    }

    #[test]
    fn tab_delimiter_is_chosen_when_columns_agree() {
        let text = "索引\t内容\n1\tVCpwd: abc\n2\t备注\n";
        let parsed = parse(text);
        assert_eq!(parsed.delimiter, '\t');
        assert_eq!(parsed.records[1].fields, vec!["1", "VCpwd: abc"]);
    }

    #[test]
    fn comma_wins_for_single_column_text() {
        let text = "内容\r\nVCpwd: abc\r\n";
        let parsed = parse(text);
        assert_eq!(parsed.delimiter, ',');
        assert_eq!(parsed.records[0].fields, vec!["内容"]);
        assert!(parsed.delimiter_basis.contains("未形成稳定"));
    }

    #[test]
    fn unclosed_quote_is_reported_as_structural_error() {
        let parsed = parse("a,b\n\"unclosed,2\n");
        assert_eq!(parsed.structural_errors, vec![2]);
        assert!(parsed.records[1]
            .issues
            .iter()
            .any(|issue| issue.contains("未闭合")));
    }

    #[test]
    fn blank_and_separator_only_lines_are_not_records() {
        let parsed = parse("a,b\n1,2\n\n,,\n3,4\n");
        assert_eq!(parsed.records.len(), 3);
        assert_eq!(
            parsed
                .records
                .iter()
                .map(|record| record.index)
                .collect::<Vec<_>>(),
            vec![1, 2, 5]
        );
    }

    #[test]
    fn header_decision_covers_bare_key_and_vcpwd_first_record() {
        let parsed = parse("VCpwd: abc,1\n备注,x\n");
        assert!(!header_decision(&parsed.records).has_header);
        let parsed = parse("索引,内容\n1,备注\n");
        assert!(header_decision(&parsed.records).has_header);
        let parsed = parse("索引,VCpwd\n1,VCpwd: abc\n");
        let decision = header_decision(&parsed.records);
        assert!(decision.has_header);
        assert!(decision.basis.contains("判为表头"));
        let parsed = parse("");
        assert!(!header_decision(&parsed.records).has_header);
    }
}
