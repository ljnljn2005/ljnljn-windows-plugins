//! 纯字节解析：腾讯 QQ 安装日志 `qq_setup.log`。
//!
//! 本模块不接触宿主、文件句柄或时钟，输入只有文件字节与一个来源标识，因此可以
//! 用合成日志完整做单元测试。
//!
//! 解析规则（与需求逐条对应）：
//!
//! 1. **编码**：先按 UTF-8（允许带 BOM）严格解码；失败按 GBK 解码；再失败按
//!    UTF-8 替换字符降级（`String::from_utf8_lossy`），永不中断。
//! 2. **行**：按 `\n` / `\r\n` / `\r` 切物理行，行号从 1 开始；末尾换行不额外
//!    产出一行。空文件得到 0 行、0 事件。
//! 3. **时间片段**：正则 `\d{4}/\d{6}`，即 4 位月日 + `/` + 6 位时分秒，
//!    `timeRaw` 保留命中的原始文本。只做 ASCII 数字匹配（`\d` 不是
//!    Unicode 数字），避免全角数字被误认。
//! 4. **分类**：只在该行内做**大小写不敏感**关键字匹配，
//!    `setup`/`install`/`开始安装`/`正在安装` → `install`；
//!    `完成`/`complete`/`success` → `complete`；
//!    `Show QQ Window`/`启动`/`launch` → `launch`；其余含时间的行 → `other`。
//!    同一行命中多类时的优先级见 [`CATEGORY_PRECEDENCE`]，输出保留全部命中类别。
//! 5. **顺序**：事件按日志行序输出，不按时间重排，不补年份、不做时区换算。
//! 6. **不丢弃**：月日或时分秒越界（month 1–12、day 1–31、hour 0–23、
//!    minute/second 0–59 之外）的数值原样保留，同时写入 limitations。
//! 7. **多命中**：同一行出现多个时间片段时，每个片段都是一条独立事件，记录其
//!    在 `lineText` 中的字符偏移；这条规则也写入 limitations。

use encoding_rs::GBK;

/// 单个输入文件的字节上限。超限返回错误而不是截断，避免半份日志产生错误的
/// `lineCount` / `unparsedLineCount`。
pub const MAX_INPUT_BYTES: usize = 16 * 1024 * 1024;

/// `lineText` 的截断长度（按 Unicode 字符计，不是字节）。
pub const LINE_TEXT_CAP: usize = 200;

/// `limitations` 条的条数上限。
pub const MAX_LIMITATIONS: usize = 200;

/// 降级解码中至少连续出现多少个 U+FFFD 才算一段「乱码字节段」。
pub const GARBLED_RUN_MIN: usize = 2;

/// 时间片段的手工扫描实现（见 [`find_times`]）：4 位月日、斜杠、6 位时分秒。
/// 只接受 ASCII 数字并拒绝紧贴数字的窗口，因此等价于正则
/// `(?<![0-9])[0-9]{4}/[0-9]{6}(?![0-9])`；这里不用正则引擎——既不需要额外依赖，
/// 也不会把 Unicode 数字当成 ASCII 数字。该常量同时作为输出到 limitations 的规则说明。
pub const TIME_RULE: &str = "(?<![0-9])[0-9]{4}/[0-9]{6}(?![0-9])";

/// 月日 / 时分秒的合法范围，越界只记 limitations，不丢事件。
pub const MONTH_RANGE: (u32, u32) = (1, 12);
pub const DAY_RANGE: (u32, u32) = (1, 31);
pub const HOUR_RANGE: (u32, u32) = (0, 23);
pub const MINUTE_RANGE: (u32, u32) = (0, 59);
pub const SECOND_RANGE: (u32, u32) = (0, 59);

/// 行分类优先级：同一行命中多类时取最靠前者，并把全部命中类别记入
/// `qqsetup.category_hits`。
pub const CATEGORY_PRECEDENCE: [Category; 3] =
    [Category::Complete, Category::Launch, Category::Install];

/// 每类关键字（全部按大小写不敏感比较）。
pub const INSTALL_KEYWORDS: [&str; 4] = ["setup", "install", "开始安装", "正在安装"];
pub const COMPLETE_KEYWORDS: [&str; 3] = ["完成", "complete", "success"];
pub const LAUNCH_KEYWORDS: [&str; 3] = ["show qq window", "启动", "launch"];

/// 事件分类。
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Category {
    Install,
    Complete,
    Launch,
    Other,
}

impl Category {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Install => "install",
            Self::Complete => "complete",
            Self::Launch => "launch",
            Self::Other => "other",
        }
    }
}

/// 实际使用的解码路径。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodePath {
    /// 严格 UTF-8（可能带 BOM）。
    Utf8,
    /// 严格 UTF-8 失败后按 GBK 解码。
    Gbk,
    /// 两种编码都失败，UTF-8 替换字符降级。
    Lossy,
}

impl DecodePath {
    /// 输出字段 `encoding` 的取值。
    #[allow(dead_code)] // The v2 record uses enum choice ids; kept from the v1 parser.
    pub fn encoding_label(self) -> &'static str {
        match self {
            Self::Utf8 => "utf-8",
            Self::Gbk => "gbk",
            Self::Lossy => "utf-8-lossy",
        }
    }
}

/// 解码后的文本与解码结论。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decoded {
    pub text: String,
    pub path: DecodePath,
    pub had_bom: bool,
    /// 使用替换字符降级时出现的 U+FFFD 个数。
    pub replacement_chars: usize,
    /// 降级解码中达到 [`GARBLED_RUN_MIN`] 的连续损坏段数。
    pub garbled_runs: usize,
    pub limitations: Vec<String>,
}

const BOM_UTF8: [u8; 3] = [0xEF, 0xBB, 0xBF];

/// 按「UTF-8（含 BOM）→ GBK → 替换字符降级」的顺序解码。
pub fn decode(bytes: &[u8]) -> Decoded {
    let (body, had_bom) = match bytes.strip_prefix(&BOM_UTF8) {
        Some(rest) => (rest, true),
        None => (bytes, false),
    };

    // 严格 UTF-8：BOM 已剥离。
    if let Ok(text) = std::str::from_utf8(body) {
        let text = text.strip_prefix('\u{feff}').unwrap_or(text);
        let mut limitations = Vec::new();
        if had_bom {
            limitations
                .push("输入以 UTF-8 BOM（EF BB BF）开头，已剥离 BOM 后按 UTF-8 解码".to_string());
        }
        return Decoded {
            text: text.to_string(),
            path: DecodePath::Utf8,
            had_bom,
            replacement_chars: 0,
            garbled_runs: 0,
            limitations,
        };
    }

    // 严格 GBK。注意 encoding_rs 在 error mode 同为 REPLACE 时 `decode` 不报错，
    // 因此必须用 …_without_replacement 取得 Option，`None` 才表示存在无法解码的字节。
    if let Some(text) = GBK.decode_without_bom_handling_and_without_replacement(body) {
        let text = text.strip_prefix('\u{feff}').unwrap_or(&text).to_string();
        let mut limitations = vec![
            "文件不是合法 UTF-8，已按 GBK 解码；两套编码对同一字节序列可能都给出一段合法文本，编码判定因此是启发式的，个别字符可能被错误显示"
                .to_string(),
        ];
        if had_bom {
            limitations.push(
                "输入以 UTF-8 BOM 开头但正文不是合法 UTF-8：BOM 已剥离后按 GBK 解码，需人工复核首行"
                    .to_string(),
            );
        }
        return Decoded {
            text,
            path: DecodePath::Gbk,
            had_bom,
            replacement_chars: 0,
            garbled_runs: 0,
            limitations,
        };
    }

    // 兜底：UTF-8 替换字符降级，永不中断。
    let lossy = String::from_utf8_lossy(body).into_owned();
    let replacement_chars = lossy.matches('\u{fffd}').count();
    let garbled_runs = count_garbled_runs(&lossy);
    let mut limitations = vec![format!(
        "文件既不是合法 UTF-8 也不是合法 GBK，已按 UTF-8 替换字符（U+FFFD）降级解码：{replacement_chars} 个替换字符、{garbled_runs} 段连续损坏，相关行的原文不可完整恢复"
    )];
    if had_bom {
        limitations
            .push("输入以 UTF-8 BOM 开头但正文不是合法 UTF-8，已剥离 BOM 后降级解码".to_string());
    }
    Decoded {
        text: lossy,
        path: DecodePath::Lossy,
        had_bom,
        replacement_chars,
        garbled_runs,
        limitations,
    }
}

/// 统计达到 [`GARBLED_RUN_MIN`] 长度的 U+FFFD 连续段。
fn count_garbled_runs(text: &str) -> usize {
    let mut runs = 0;
    let mut run = 0;
    for character in text.chars() {
        if character == '\u{fffd}' {
            run += 1;
        } else {
            if run >= GARBLED_RUN_MIN {
                runs += 1;
            }
            run = 0;
        }
    }
    if run >= GARBLED_RUN_MIN {
        runs += 1;
    }
    runs
}

/// 按 `\n` / `\r\n` / `\r` 切物理行，不带末尾空行，行号 = 下标 + 1。
pub fn split_lines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let bytes = text.as_bytes();
    let mut start = 0;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\n' => {
                lines.push(&text[start..index]);
                start = index + 1;
                index += 1;
            }
            b'\r' => {
                lines.push(&text[start..index]);
                index += if bytes.get(index + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                };
                start = index;
            }
            _ => index += 1,
        }
    }
    if start < bytes.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// 一个已定位的时间片段（相对 `lineText`）。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeHit {
    /// 命中的原始文本，例如 `0831/180025`。
    pub time_raw: String,
    /// 命中起点在整行原始文本中的字符偏移。
    pub char_offset: usize,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    /// 月日或时分秒越界时的说明。
    pub bounds_issue: Option<String>,
}

/// 一行日志的解析结果（对外输出走 [`Event`]；此结构保留整行信息便于复核）。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParsedLine {
    /// 1 起算的行号。
    pub line_no: usize,
    /// 整行原文（未截断）。
    pub line_text: String,
    /// 整行字符数（截断前）。
    pub line_chars: usize,
    /// 每个时间片段一条，保持从左到右的原始顺序。
    pub times: Vec<TimeHit>,
    pub category: Option<Category>,
    pub category_hits: Vec<Category>,
}

impl ParsedLine {
    /// 解析一行（`line_no` 从 1 起算）。
    pub fn parse(line_no: usize, line: &str) -> Self {
        let times = find_times(line);
        let category_hits = if times.is_empty() {
            Vec::new()
        } else {
            classify(line)
        };
        let category = if times.is_empty() {
            None
        } else {
            Some(primary_category(&category_hits))
        };
        Self {
            line_no,
            line_text: line.to_string(),
            line_chars: line.chars().count(),
            times,
            category,
            category_hits,
        }
    }
}

fn is_ascii_digit(byte: u8) -> bool {
    byte.is_ascii_digit()
}

fn in_range(value: u32, (low, high): (u32, u32)) -> bool {
    (low..=high).contains(&value)
}

/// 在 `line` 中找出所有 `dddd/dddddd` 片段，保持原始位置顺序。
///
/// 只接受**完整数字串**：命中片段左右两侧都不能紧贴数字，因此
/// `0831/1800255`（斜杠后 7 位）或 `08311/180025` 不会被截取成看似合法的片段。
pub fn find_times(line: &str) -> Vec<TimeHit> {
    let bytes = line.as_bytes();
    let mut hits = Vec::new();
    let mut index = 0;
    // 4 位 + '/' + 6 位 = 11 字节。
    while index + 11 <= bytes.len() {
        let window = &bytes[index..index + 11];
        let shape = window[0..4].iter().all(|byte| is_ascii_digit(*byte))
            && window[4] == b'/'
            && window[5..11].iter().all(|byte| is_ascii_digit(*byte));
        if !shape {
            index += 1;
            continue;
        }
        // 片段两侧（不含片段自身的字节）都不能紧贴数字。
        let glued = index
            .checked_sub(1)
            .is_some_and(|before| is_ascii_digit(bytes[before]))
            || bytes
                .get(index + 11)
                .is_some_and(|byte| is_ascii_digit(*byte));
        if glued {
            index += 1;
            continue;
        }
        // 位置一定是合法 UTF-8 边界：匹配到的 11 个字节全是 ASCII。
        let raw = &line[index..index + 11];
        let month = digits(raw, 0, 2);
        let day = digits(raw, 2, 4);
        let hour = digits(raw, 5, 7);
        let minute = digits(raw, 7, 9);
        let second = digits(raw, 9, 11);
        let mut issues = Vec::new();
        if !in_range(month, MONTH_RANGE) || !in_range(day, DAY_RANGE) {
            issues.push(format!(
                "月日 {raw} 越界（month 应在 {}-{}、day 应在 {}-{}）",
                MONTH_RANGE.0, MONTH_RANGE.1, DAY_RANGE.0, DAY_RANGE.1
            ));
        }
        if !in_range(hour, HOUR_RANGE)
            || !in_range(minute, MINUTE_RANGE)
            || !in_range(second, SECOND_RANGE)
        {
            issues.push(format!(
                "时分秒 {raw} 越界（hour 应 ≤{}、minute/second 应 ≤{}）",
                HOUR_RANGE.1, SECOND_RANGE.1
            ));
        }
        hits.push(TimeHit {
            time_raw: raw.to_string(),
            char_offset: line[..index].chars().count(),
            month,
            day,
            hour,
            minute,
            second,
            bounds_issue: if issues.is_empty() {
                None
            } else {
                Some(issues.join("；"))
            },
        });
        index += 11;
    }
    hits
}

fn digits(raw: &str, start: usize, end: usize) -> u32 {
    raw[start..end]
        .bytes()
        .fold(0_u32, |value, byte| value * 10 + u32::from(byte - b'0'))
}

/// 大小写不敏感的关键字包含判断（Unicode 简单大小写折叠）。
pub fn contains_ignore_case(line: &str, keyword: &str) -> bool {
    if keyword.is_empty() {
        return true;
    }
    // 逐字符折叠后做子串查找：先折叠行，再折叠关键字；因为折叠是逐字符的、
    // 不改变字符边界，折叠后的子串命中即对应原行的命中。
    let folded_line: String = line.chars().flat_map(lowercase_chars).collect();
    let folded_keyword: String = keyword.chars().flat_map(lowercase_chars).collect();
    folded_line.contains(&folded_keyword)
}

fn lowercase_chars(character: char) -> Vec<char> {
    let folded: Vec<char> = character.to_lowercase().collect();
    if folded.is_empty() {
        vec![character]
    } else {
        folded
    }
}

/// 行内命中的全部类别（按 [`CATEGORY_PRECEDENCE`] 排列顺序去重）。
pub fn classify(line: &str) -> Vec<Category> {
    let mut hits = Vec::new();
    let mut push = |category: Category, matched: bool| {
        if matched && !hits.contains(&category) {
            hits.push(category);
        }
    };
    push(
        Category::Complete,
        COMPLETE_KEYWORDS
            .iter()
            .any(|keyword| contains_ignore_case(line, keyword)),
    );
    push(
        Category::Launch,
        LAUNCH_KEYWORDS
            .iter()
            .any(|keyword| contains_ignore_case(line, keyword)),
    );
    push(
        Category::Install,
        INSTALL_KEYWORDS
            .iter()
            .any(|keyword| contains_ignore_case(line, keyword)),
    );
    hits
}

/// 按 [`CATEGORY_PRECEDENCE`] 选出唯一类别；没有任何关键字命中时为 `Other`。
pub fn primary_category(hits: &[Category]) -> Category {
    CATEGORY_PRECEDENCE
        .iter()
        .copied()
        .find(|category| hits.contains(category))
        .unwrap_or(Category::Other)
}

/// 截断到 [`LINE_TEXT_CAP`] 个字符。
pub fn truncate_line(line: &str) -> (String, usize) {
    let total = line.chars().count();
    if total <= LINE_TEXT_CAP {
        return (line.to_string(), total);
    }
    (line.chars().take(LINE_TEXT_CAP).collect(), total)
}

/// 一条时间事件的解析结果（尚未附加来源标识）。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Event {
    pub line_no: usize,
    pub time_raw: String,
    pub month: u32,
    pub day: u32,
    pub hour: u32,
    pub minute: u32,
    pub second: u32,
    pub category: Category,
    pub category_hits: Vec<Category>,
    pub line_text: String,
    pub line_chars: usize,
    pub char_offset: usize,
}

/// 整个文件的解析结果。
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Timeline {
    pub encoding: DecodePath,
    pub line_count: usize,
    pub events: Vec<Event>,
    pub unparsed_line_count: usize,
    /// 空行条数（计入 `unparsed_line_count`，另列便于复核）。
    pub blank_line_count: usize,
    pub limitations: Vec<String>,
}

/// 解析整份日志。`source_ref` 只用于 limitations 的定位文案（例如 `qq_setup.log#L3`）。
pub fn parse(bytes: &[u8], source_ref: &str) -> Result<Timeline, String> {
    if bytes.len() > MAX_INPUT_BYTES {
        return Err(format!(
            "输入 {} 字节超过上限 {} 字节，未解析（不做截断以免得到不完整的行计数）",
            bytes.len(),
            MAX_INPUT_BYTES
        ));
    }
    Ok(parse_timeline(&decode(bytes), source_ref))
}

/// 对已解码文本构建时间线（不含字节上限检查）。
pub fn parse_timeline(decoded: &Decoded, source_ref: &str) -> Timeline {
    let lines = split_lines(&decoded.text);
    let mut events = Vec::new();
    let mut unparsed_line_count = 0;
    let mut blank_line_count = 0;
    let mut notes: Vec<String> = decoded.limitations.clone();
    let mut bounds_hits = 0_usize;
    let mut multi_hits = 0_usize;
    let mut other_hits = 0_usize;
    let mut truncated_tail_hits = 0_usize;

    for (index, line) in lines.iter().enumerate() {
        let parsed = ParsedLine::parse(index + 1, line);
        if parsed.times.is_empty() {
            unparsed_line_count += 1;
            if line.trim().is_empty() {
                blank_line_count += 1;
            }
            continue;
        }
        // 时间片段在 200 字符之后的行：事件照常输出，但 lineText 里看不到片段，
        // 因此单独记一条 limitation，免得复核者以为片段丢了。
        if parsed
            .times
            .iter()
            .any(|hit| hit.char_offset >= LINE_TEXT_CAP)
        {
            truncated_tail_hits += 1;
        }
        let line_no = parsed.line_no;
        let (line_text, line_chars) = truncate_line(line);
        let category = parsed.category.unwrap_or(Category::Other);
        if category == Category::Other {
            other_hits += 1;
        }
        if parsed.times.len() > 1 {
            multi_hits += 1;
            push_note(
                &mut notes,
                format!(
                    "{source_ref}#L{line_no} 同一行出现 {} 个时间片段，已各输出一条事件，不判断先后语义",
                    parsed.times.len()
                ),
            );
        }
        for hit in parsed.times {
            if let Some(issue) = &hit.bounds_issue {
                bounds_hits += 1;
                push_note(
                    &mut notes,
                    format!(
                        "{source_ref}#L{line_no} 时间片段 {} 越界：{issue}；原值保留未丢弃",
                        hit.time_raw
                    ),
                );
            }
            events.push(Event {
                line_no,
                time_raw: hit.time_raw,
                month: hit.month,
                day: hit.day,
                hour: hit.hour,
                minute: hit.minute,
                second: hit.second,
                category,
                category_hits: parsed.category_hits.clone(),
                line_text: line_text.clone(),
                line_chars,
                char_offset: hit.char_offset,
            });
        }
    }

    if !decoded.text.is_empty() && decoded.text.ends_with(['\n', '\r']) {
        push_note(
            &mut notes,
            "文件以换行符结尾，末尾换行不产生额外空行，行号与文本编辑器一致".to_string(),
        );
    }
    if lines.is_empty() {
        push_note(
            &mut notes,
            "输入为空（0 字节），返回 0 事件，不报错".to_string(),
        );
    }
    push_note(
        &mut notes,
        format!(
            "时间片段只按 {TIME_RULE} 抽取（ASCII 数字、完整数字串），抽取到即原样保留；月日与时分秒不做日历校验，越界值见下方逐条说明"
        ),
    );
    push_note(
        &mut notes,
        "未补年份、未做时区换算：只保留 mmdd/hhmmss 原值，跨年与跨时区先后不做推断".to_string(),
    );
    push_note(
        &mut notes,
        "事件按日志行序输出（同一行多个片段按从左到右），不按时间重排".to_string(),
    );
    push_note(
        &mut notes,
        "分类只做同行大小写不敏感关键字匹配；同一行命中多类时按 complete > launch > install 取主类别，全部命中类别见 qqsetup.category_hits；仅由标记行（无时间片段）表达的状态不会被并入事件"
            .to_string(),
    );
    push_note(
        &mut notes,
        "编码判定是启发式的：GBK 能解码几乎所有字节序列，合法 UTF-8 的字节也常能被 GBK 解码出「另一个字符」；因此先 UTF-8 后 GBK 的顺序只能保证不乱码中断，不能保证字符正确。同一文件中混有 GBK 行与不可恢复坏字节时，整体走降级路径，GBK 行会显示为 U+FFFD".to_string(),
    );
    push_note(
        &mut notes,
        format!(
            "未解出的未覆盖项：跨年月/年份推断、QQ 使用时段结论、与安装软件或最近访问 csv 的关联、QQ.exe 版本校验、时区换算（{unparsed_line_count} 行无时间戳，其中 {blank_line_count} 行为空行）"
        ),
    );
    if other_hits > 0 {
        push_note(
            &mut notes,
            format!("{other_hits} 行含时间片段但未命中任何安装/完成/启动关键字，归类 other"),
        );
    }
    if truncated_tail_hits > 0 {
        push_note(
            &mut notes,
            format!(
                "{truncated_tail_hits} 行的时间片段位于第 {LINE_TEXT_CAP} 个字符之后：事件照常输出并带 qqsetup.char_offset，但 line_text 被截断后看不到该片段，复核这类行请把 char_offset 与 qqsetup.line_chars 一并参考"
            ),
        );
    }
    let _ = (bounds_hits, multi_hits);

    Timeline {
        encoding: decoded.path,
        line_count: lines.len(),
        events,
        unparsed_line_count,
        blank_line_count,
        limitations: notes,
    }
}

fn push_note(notes: &mut Vec<String>, note: String) {
    if notes.len() < MAX_LIMITATIONS && !notes.contains(&note) {
        notes.push(note);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_str(bytes: &[u8]) -> Timeline {
        parse(bytes, "qq_setup.log").expect("input within cap")
    }

    fn gbk(text: &str) -> Vec<u8> {
        let (bytes, _, unmappable) = GBK.encode(text);
        assert!(!unmappable, "test fixture must be representable in GBK");
        bytes.into_owned()
    }

    // ---- 编码 ----

    #[test]
    fn utf8_with_and_without_bom_use_same_path() {
        let plain = b"0831/180025 start setup\n".to_vec();
        let mut bom = BOM_UTF8.to_vec();
        bom.extend_from_slice(&plain);
        let a = parse_str(&plain);
        let b = parse_str(&bom);
        assert_eq!(a.encoding, DecodePath::Utf8);
        assert_eq!(b.encoding, DecodePath::Utf8);
        assert_eq!(a.events, b.events);
        assert_eq!(a.line_count, 1);
        assert!(b.limitations.iter().any(|note| note.contains("UTF-8 BOM")));
    }

    #[test]
    fn bom_inside_text_is_stripped_once() {
        let mut bytes = BOM_UTF8.to_vec();
        bytes.extend_from_slice("0831/180025 开始安装\r\n".as_bytes());
        let timeline = parse_str(&bytes);
        assert_eq!(timeline.events[0].line_no, 1);
        assert!(timeline.events[0].line_text.starts_with("0831/180025"));
    }

    #[test]
    fn gbk_fallback_decodes_chinese_keywords() {
        let bytes = gbk("0831/180025 开始安装 QQ\r\n0831/180708 安装完成 Show QQ Window\r\n");
        let timeline = parse_str(&bytes);
        assert_eq!(timeline.encoding, DecodePath::Gbk);
        assert_eq!(timeline.events.len(), 2);
        assert_eq!(timeline.events[0].category, Category::Install);
        assert_eq!(
            timeline.events[1].line_text,
            "0831/180708 安装完成 Show QQ Window"
        );
        assert_eq!(
            timeline.events[1].category_hits,
            vec![Category::Complete, Category::Launch]
        );
        assert!(timeline
            .limitations
            .iter()
            .any(|note| note.contains("按 GBK 解码")));
    }

    #[test]
    fn lossy_fallback_never_aborts_and_keeps_later_lines() {
        // 0xFF 在任何合法 UTF-8 / GBK 序列中都不成立。
        let mut bytes = b"0831/180025 setup\n".to_vec();
        bytes.extend_from_slice(&[0xFF, 0xFE, 0xFF]);
        bytes.extend_from_slice(b"\n0831/180708 complete\n");
        let timeline = parse_str(&bytes);
        assert_eq!(timeline.encoding, DecodePath::Lossy);
        assert_eq!(timeline.line_count, 3);
        assert_eq!(timeline.events.len(), 2);
        assert_eq!(timeline.events[0].line_no, 1);
        assert_eq!(timeline.events[1].line_no, 3);
        assert_eq!(timeline.unparsed_line_count, 1);
        assert!(timeline
            .limitations
            .iter()
            .any(|note| note.contains("U+FFFD")));
    }

    #[test]
    fn garbled_run_counting_needs_two_replacements() {
        assert_eq!(count_garbled_runs("\u{fffd}ab"), 0);
        assert_eq!(count_garbled_runs("a\u{fffd}\u{fffd}b"), 1);
        assert_eq!(count_garbled_runs("\u{fffd}\u{fffd}x\u{fffd}\u{fffd}"), 2);
        assert_eq!(count_garbled_runs("clean"), 0);
    }

    #[test]
    fn pure_ascii_is_utf8_not_gbk() {
        let timeline = parse_str(b"0101/000000 launch\n");
        assert_eq!(timeline.encoding, DecodePath::Utf8);
    }

    // ---- 行切分 ----

    #[test]
    fn line_splitting_handles_all_separators_without_trailing_line() {
        assert_eq!(split_lines("").len(), 0);
        assert_eq!(split_lines("a"), vec!["a"]);
        assert_eq!(split_lines("a\r\nb\rc\n"), vec!["a", "b", "c"]);
        assert_eq!(split_lines("a\n\nb"), vec!["a", "", "b"]);
        assert_eq!(split_lines("\r\n"), vec![""]);
    }

    #[test]
    fn crlf_input_keeps_line_numbers_and_has_no_carriage_return() {
        let timeline = parse_str(b"0831/180025 setup\r\n0831/180708 complete\r\n");
        assert_eq!(timeline.line_count, 2);
        assert_eq!(timeline.events.len(), 2);
        assert_eq!(timeline.events[1].line_no, 2);
        assert!(!timeline.events[1].line_text.contains('\r'));
    }

    // ---- 时间片段 ----

    #[test]
    fn time_fragment_fields_are_split_without_year_or_timezone() {
        let hits = find_times("0831/180025 安装完成");
        assert_eq!(hits.len(), 1);
        let hit = &hits[0];
        assert_eq!(hit.time_raw, "0831/180025");
        assert_eq!((hit.month, hit.day), (8, 31));
        assert_eq!((hit.hour, hit.minute, hit.second), (18, 0, 25));
        assert_eq!(hit.char_offset, 0);
        assert_eq!(hit.bounds_issue, None);
    }

    #[test]
    fn time_fragment_must_be_a_complete_digit_run() {
        for text in [
            "831/180025",
            "0831/18002",
            "0831/1800255",
            "08311/180025",
            "0831/18002555",
            "08-31/180025",
            "0831-180025",
            "０８３１/180025",
            "０831/180025",
            "",
        ] {
            assert!(find_times(text).is_empty(), "unexpected match in {text:?}");
        }
        let hit = &find_times("x0831/180025y")[0];
        assert_eq!(hit.time_raw, "0831/180025");
        assert_eq!(hit.char_offset, 1);
        assert_eq!(find_times("(0831/180025)")[0].time_raw, "0831/180025");
    }

    #[test]
    fn out_of_bounds_values_are_kept_and_reported() {
        let hits = find_times("1332/256199 boundary");
        assert_eq!(hits.len(), 1);
        let hit = &hits[0];
        assert_eq!((hit.month, hit.day), (13, 32));
        assert_eq!((hit.hour, hit.minute, hit.second), (25, 61, 99));
        let issue = hit.bounds_issue.as_deref().expect("bounds issue");
        assert!(issue.contains("13"));
        assert!(issue.contains("256199"));

        let timeline = parse_str(b"1332/256199 setup\n");
        assert_eq!(timeline.events.len(), 1);
        assert_eq!(timeline.events[0].time_raw, "1332/256199");
        assert!(timeline
            .limitations
            .iter()
            .any(|note| note.contains("qq_setup.log#L1") && note.contains("越界")));
    }

    #[test]
    fn multiple_time_fragments_on_one_line_are_all_kept_in_order() {
        let timeline = parse_str(b"0831/180025 0831/180708 complete\n");
        assert_eq!(timeline.events.len(), 2);
        assert_eq!(timeline.events[0].time_raw, "0831/180025");
        assert_eq!(timeline.events[1].time_raw, "0831/180708");
        assert_eq!(timeline.events[0].char_offset, 0);
        assert_eq!(timeline.events[1].char_offset, 12);
        assert_eq!(timeline.events[0].line_no, timeline.events[1].line_no);
        assert!(timeline
            .limitations
            .iter()
            .any(|note| note.contains("同一行出现 2 个时间片段")));
    }

    // ---- 分类 ----

    #[test]
    fn classification_is_case_insensitive_and_chinese_aware() {
        assert_eq!(
            primary_category(&classify("SETUP begin")),
            Category::Install
        );
        assert_eq!(
            primary_category(&classify("InStAlL files")),
            Category::Install
        );
        assert_eq!(primary_category(&classify("开始安装")), Category::Install);
        assert_eq!(
            primary_category(&classify("正在安装组件")),
            Category::Install
        );
        assert_eq!(primary_category(&classify("COMPLETE")), Category::Complete);
        assert_eq!(primary_category(&classify("Success!")), Category::Complete);
        assert_eq!(primary_category(&classify("安装完成")), Category::Complete);
        assert_eq!(
            primary_category(&classify("SHOW QQ WINDOW")),
            Category::Launch
        );
        assert_eq!(
            primary_category(&classify("show qq window")),
            Category::Launch
        );
        assert_eq!(primary_category(&classify("启动 QQ")), Category::Launch);
        assert_eq!(primary_category(&classify("LAUNCH")), Category::Launch);
        assert_eq!(primary_category(&classify("nothing here")), Category::Other);
    }

    #[test]
    fn mixed_line_keeps_primary_and_all_hits() {
        let timeline = parse_str("0831/180708 安装完成 Show QQ Window\r\n".as_bytes());
        let event = &timeline.events[0];
        assert_eq!(event.category, Category::Complete);
        assert_eq!(
            event.category_hits,
            vec![Category::Complete, Category::Launch]
        );
        assert_eq!(event.category_hits[0].as_str(), "complete");
        assert_eq!(event.category_hits[1].as_str(), "launch");
    }

    #[test]
    fn classification_ignores_marker_only_lines_for_event_extraction() {
        let timeline = parse_str(b"setup\r\n0831/180025 working\r\n");
        assert_eq!(timeline.events.len(), 1);
        assert_eq!(timeline.events[0].category, Category::Other);
        assert_eq!(timeline.unparsed_line_count, 1);
        assert!(timeline
            .limitations
            .iter()
            .any(|note| note.contains("1 行含时间片段但未命中")));
    }

    #[test]
    fn case_folding_is_ascii_and_unicode_simple() {
        assert!(contains_ignore_case("SETUP", "setup"));
        assert!(contains_ignore_case("SeTuP", "setup"));
        // 全角输入不折叠为 ASCII，不做 NFKC 归一化（只做大小写折叠）。
        assert!(!contains_ignore_case(
            "ＳＨＯＷ ＱＱ ＷＩＮＤＯＷ",
            "show qq window"
        ));
        // 逐字符折叠：İ 折叠为 i + U+0307，因此 `İnstall` 里没有连续的 `install`。
        assert!(!contains_ignore_case("İNSTALL", "install"));
        assert!(!contains_ignore_case("İnstall", "install"));
        // 中文关键字不受大小写影响。
        assert!(contains_ignore_case("已经安装完成", "完成"));
        assert!(!contains_ignore_case("已经装完", "完成"));
    }

    #[test]
    fn bom_only_input_is_zero_lines_with_bom_note() {
        let timeline = parse_str(&BOM_UTF8);
        assert_eq!(timeline.encoding, DecodePath::Utf8);
        assert_eq!(timeline.line_count, 0);
        assert_eq!(timeline.events.len(), 0);
        assert!(timeline
            .limitations
            .iter()
            .any(|note| note.contains("UTF-8 BOM") && note.contains("已剥离")));
    }

    #[test]
    fn file_of_only_blank_lines_counts_every_line_as_unparsed() {
        let timeline = parse_str(b"\r\n\r\n\r\n");
        assert_eq!(timeline.line_count, 3, "末尾换行不产生第 4 行");
        assert_eq!(timeline.events.len(), 0);
        assert_eq!(timeline.unparsed_line_count, 3);
        assert_eq!(timeline.blank_line_count, 3);
        assert!(!timeline
            .limitations
            .iter()
            .any(|note| note.contains("输入为空")));
    }

    #[test]
    fn time_fragment_after_the_200_char_window_is_flagged() {
        let line = format!("{}0831/180025 complete", "x".repeat(300));
        let timeline = parse_str(line.as_bytes());
        assert_eq!(timeline.events.len(), 1);
        assert_eq!(timeline.events[0].line_no, 1);
        assert_eq!(timeline.events[0].char_offset, 300);
        assert_eq!(timeline.events[0].line_chars, line.chars().count());
        assert!(!timeline.events[0].line_text.contains("0831/180025"));
        assert!(timeline
            .limitations
            .iter()
            .any(|note| note.contains("字符之后") && note.contains("char_offset")));
    }

    #[test]
    fn utf16_input_degrades_instead_of_failing() {
        // UTF-16LE 日志（无 BOM 识别，直接按字节处理）：不得 panic，不得中断。
        let mut bytes = Vec::new();
        for word in "0831/180025 setup\n".encode_utf16() {
            bytes.extend(word.to_le_bytes());
        }
        let timeline = parse_str(&bytes);
        assert!(matches!(
            timeline.encoding,
            DecodePath::Lossy | DecodePath::Gbk | DecodePath::Utf8
        ));
        // NUL 字节不会与 ASCII 数字拼成片段，因此 UTF-16 文本识别不出事件；关键是
        // 不 panic、不中断，且每一行都被计入「事件」或「未解析」，没有行被吞掉。
        assert_eq!(timeline.events.len(), 0);
        assert_eq!(timeline.unparsed_line_count, timeline.line_count);
        assert!(timeline.line_count >= 1);
        assert!(
            !timeline.limitations.is_empty(),
            "降级解码必须留下可复核的 limitation"
        );
    }

    // ---- 输出字段 ----

    #[test]
    fn line_text_is_truncated_to_200_chars_but_counts_stay_exact() {
        let long = format!("0831/180025 setup {}", "长".repeat(300));
        let timeline = parse_str(long.as_bytes());
        let event = &timeline.events[0];
        assert_eq!(event.line_text.chars().count(), LINE_TEXT_CAP);
        assert_eq!(event.line_chars, long.chars().count());
        assert_eq!(timeline.line_count, 1);
    }

    #[test]
    fn empty_input_is_zero_events_not_an_error() {
        let timeline = parse_str(b"");
        assert_eq!(timeline.encoding, DecodePath::Utf8);
        assert_eq!(timeline.line_count, 0);
        assert_eq!(timeline.events.len(), 0);
        assert_eq!(timeline.unparsed_line_count, 0);
        assert!(timeline
            .limitations
            .iter()
            .any(|note| note.contains("输入为空")));
    }

    #[test]
    fn oversized_input_is_rejected_not_truncated() {
        let error = parse(&vec![b'a'; MAX_INPUT_BYTES + 1], "qq_setup.log").expect_err("cap");
        assert!(error.contains("超过上限"));
    }

    #[test]
    fn events_keep_log_order_even_when_times_regress() {
        let timeline = parse_str(b"1201/235959 complete\n0101/000001 setup\n");
        assert_eq!(timeline.events[0].line_no, 1);
        assert_eq!(timeline.events[0].time_raw, "1201/235959");
        assert_eq!(timeline.events[1].line_no, 2);
        assert_eq!(timeline.events[1].time_raw, "0101/000001");
    }

    #[test]
    fn limitations_are_deduplicated_and_capped() {
        let mut notes = Vec::new();
        for index in 0..(MAX_LIMITATIONS + 50) {
            push_note(&mut notes, format!("note {index}"));
        }
        push_note(&mut notes, "note 0".to_string());
        assert_eq!(notes.len(), MAX_LIMITATIONS);
        assert_eq!(notes[0], "note 0");
    }

    #[test]
    fn decode_path_labels_are_stable() {
        assert_eq!(DecodePath::Utf8.encoding_label(), "utf-8");
        assert_eq!(DecodePath::Gbk.encoding_label(), "gbk");
        assert_eq!(DecodePath::Lossy.encoding_label(), "utf-8-lossy");
    }
}
