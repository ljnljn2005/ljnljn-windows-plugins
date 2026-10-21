//! Tencent QQ `qq_setup.log` time fragments (LPP v2).
//!
//! The parser is unchanged from the LPP v1 plugin: UTF-8(BOM) → GBK →
//! replacement-character decoding, `mmdd/hhmmss` fragments matched as
//! complete ASCII digit runs, case-insensitive install/complete/launch
//! classification and raw-line preservation (200 character cap).
//!
//! Each log file gets one `qqsetup.file` summary and one `qqsetup.event`
//! per time fragment. The log carries no year and no time zone, so the
//! fragments stay month/day/hour/minute/second integers plus `time_raw`;
//! emitting a `Timestamp` would require guessing and is deliberately not
//! done.

mod parser;

#[cfg(test)]
mod tests;

use lovelycarve_plugin::{export_plugin, Plugin, Record, Result, Run};

use crate::parser::{Category, DecodePath};

/// Events emitted for one log file; the v1 analyzer refused larger results.
const MAX_EVENTS: usize = 9_999;

#[derive(Record)]
#[record(id = "qqsetup.file", label = "安装日志文件", title = "{source_file}")]
struct SetupFile {
    #[field(label = "来源文件", key)]
    source_file: String,
    #[field(
        label = "编码",
        kind = "enum",
        choices = "utf_8=UTF-8,gbk=GBK,utf_8_lossy=UTF-8（替换降级）"
    )]
    encoding: String,
    #[field(label = "总行数")]
    line_count: usize,
    #[field(label = "时间事件数")]
    event_count: usize,
    #[field(label = "无时间片段行数")]
    unparsed_line_count: usize,
    #[field(label = "空行数")]
    blank_line_count: usize,
    #[field(label = "限制说明", kind = "list")]
    limitations: Vec<String>,
}

#[derive(Record)]
#[record(
    id = "qqsetup.event",
    label = "安装日志时间事件",
    title = "第 {line_no} 行 · {time_raw}"
)]
struct SetupEvent {
    #[field(label = "行号", key)]
    line_no: usize,
    #[field(label = "字符偏移", key)]
    char_offset: usize,
    #[field(label = "时间原文")]
    time_raw: String,
    #[field(label = "月")]
    month: u32,
    #[field(label = "日")]
    day: u32,
    #[field(label = "时")]
    hour: u32,
    #[field(label = "分")]
    minute: u32,
    #[field(label = "秒")]
    second: u32,
    #[field(
        label = "分类",
        kind = "enum",
        choices = "install=安装,complete=完成,launch=启动,other=其他"
    )]
    category: String,
    #[field(label = "命中类别", kind = "list")]
    category_hits: Vec<String>,
    #[field(label = "原始行")]
    line_text: String,
    #[field(label = "截断前字符数")]
    line_chars: usize,
}

fn encoding_choice(path: DecodePath) -> &'static str {
    match path {
        DecodePath::Utf8 => "utf_8",
        DecodePath::Gbk => "gbk",
        DecodePath::Lossy => "utf_8_lossy",
    }
}

fn category_choice(category: Category) -> &'static str {
    category.as_str()
}

fn qq_setup_log(run: &Run) -> Result<()> {
    let mut files = 0usize;
    let mut events = 0usize;
    let mut invalid = 0usize;

    for file in run.inputs() {
        run.check_cancelled()?;
        files += 1;
        let bytes = match file.read_all(parser::MAX_INPUT_BYTES as u64) {
            Ok(bytes) => bytes,
            Err(error) => {
                invalid += 1;
                run.warn_file(file, &error.code, error.message)?;
                continue;
            }
        };
        let timeline = match parser::parse(&bytes, file.name()) {
            Ok(timeline) => timeline,
            Err(message) => {
                invalid += 1;
                run.warn_file(
                    file,
                    "INVALID_SETUP_LOG",
                    format!("{}: {message}", file.name()),
                )?;
                continue;
            }
        };
        if timeline.events.len() > MAX_EVENTS {
            invalid += 1;
            run.warn_file(
                file,
                "RESOURCE_LIMIT",
                format!(
                    "{}: 解析出 {} 条时间事件，超过单文件 {MAX_EVENTS} 条上限；未输出部分结果，请先按行拆分日志",
                    file.name(),
                    timeline.events.len()
                ),
            )?;
            continue;
        }

        run.record(&SetupFile {
            source_file: file.name().to_owned(),
            encoding: encoding_choice(timeline.encoding).to_owned(),
            line_count: timeline.line_count,
            event_count: timeline.events.len(),
            unparsed_line_count: timeline.unparsed_line_count,
            blank_line_count: timeline.blank_line_count,
            limitations: timeline.limitations.clone(),
        })
        .from(file)
        .at(0, file.size())
        .note(file.name())
        .emit()?;

        if timeline.encoding == DecodePath::Lossy {
            run.warn_file(
                file,
                "LOSSY_DECODING",
                format!(
                    "{}: 文件既不是合法 UTF-8 也不是合法 GBK，已按替换字符（U+FFFD）降级解码；相关行原文不可完整恢复",
                    file.name()
                ),
            )?;
        }

        for event in &timeline.events {
            run.record(&SetupEvent {
                line_no: event.line_no,
                char_offset: event.char_offset,
                time_raw: event.time_raw.clone(),
                month: event.month,
                day: event.day,
                hour: event.hour,
                minute: event.minute,
                second: event.second,
                category: category_choice(event.category).to_owned(),
                category_hits: event
                    .category_hits
                    .iter()
                    .map(|category| category.as_str().to_owned())
                    .collect(),
                line_text: event.line_text.clone(),
                line_chars: event.line_chars,
            })
            .from(file)
            .note(format!("line {}", event.line_no))
            .emit()?;
        }
        events += timeline.events.len();
    }

    if run.inputs().is_empty() {
        run.warn(
            "INPUT_NOT_FOUND",
            "未选择安装日志文件；请选择 qq_setup.log 或同构文本日志",
        )?;
    }
    run.set_summary(format!(
        "读取 {files} 个日志文件，输出 {events} 条时间事件，无法解析 {invalid} 个；只保留 mmdd/hhmmss 原值，未补年份、未做时区换算。"
    ));
    Ok(())
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.qq-setup-log")
        .record::<SetupFile>()
        .record::<SetupEvent>()
        .analyzer("qq_setup_log", qq_setup_log)
}

export_plugin!(plugin);
