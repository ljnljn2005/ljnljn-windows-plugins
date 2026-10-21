//! Literal HTTP/HTTPS URLs in Windows PSReadLine history (LPP v2).
//!
//! The parser is unchanged from the LPP v1 plugin: UTF-8 / BOM UTF-16
//! decoding, logical commands (a trailing backtick joins continuation
//! lines), literal `http(s)://` extraction and per-command URLs.
//!
//! The file analyzer reads the history file the user selected; the evidence
//! analyzer walks the standard per-user PSReadLine paths on every volume of
//! the evidence item. A history file with no execution timestamps cannot
//! produce timeline events, so this plugin emits no `Timestamp` fields.

mod parser;

#[cfg(test)]
mod tests;

use lovelycarve_plugin::{export_plugin, FileRef, Plugin, Record, Result, Run};

/// Standard ConsoleHost history paths, relative to a user profile.
const RELATIVE: [&str; 2] = [
    "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
    "AppData/Roaming/Microsoft/PowerShell/PSReadLine/ConsoleHost_history.txt",
];

/// Most entries enumerated from one `Users` directory.
const MAX_USERS: usize = 512;

#[derive(Record)]
#[record(
    id = "psreadline.history",
    label = "历史文件统计",
    title = "{url_command_count} 条含 URL 命令"
)]
struct HistoryFile {
    #[field(label = "来源文件")]
    source_file: String,
    #[field(label = "命令数")]
    command_count: usize,
    #[field(label = "含 URL 命令数")]
    url_command_count: usize,
}

#[derive(Record)]
#[record(
    id = "psreadline.command",
    label = "含 URL 的历史命令",
    title = "命令 {index} · 第 {line} 行"
)]
struct HistoryCommand {
    #[field(label = "命令序号")]
    index: usize,
    #[field(label = "起始行")]
    line: usize,
    #[field(label = "命令")]
    command: String,
    #[field(label = "URL", kind = "list")]
    urls: Vec<String>,
}

#[derive(Record)]
#[record(
    id = "psreadline.total",
    label = "全部历史统计",
    title = "{url_command_count} 条含 URL 命令 / {file_count} 份历史"
)]
struct HistoryTotal {
    #[field(label = "历史文件数")]
    file_count: usize,
    #[field(label = "含 URL 命令总数")]
    url_command_count: usize,
}

/// A view path component the plugin is willing to join.
fn component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\'])
        && !name.chars().any(char::is_control)
}

/// Parses one history file and emits its typed records. Returns the number of
/// URL-bearing commands, or `None` after a warning when the file is unusable.
fn analyze_file(run: &Run, file: &FileRef, source_file: &str, note: &str) -> Result<Option<usize>> {
    let bytes = match file.read_all(parser::MAX_BYTES as u64) {
        Ok(bytes) => bytes,
        Err(error) => {
            run.warn_file(file, &error.code, error.message)?;
            return Ok(None);
        }
    };
    let history = match parser::parse(&bytes) {
        Ok(history) => history,
        Err(message) => {
            run.warn_file(file, "INVALID_HISTORY", format!("{source_file}: {message}"))?;
            return Ok(None);
        }
    };

    run.record(&HistoryFile {
        source_file: source_file.to_owned(),
        command_count: history.commands,
        url_command_count: history.matches.len(),
    })
    .from(file)
    .note(note)
    .emit()?;

    for command in &history.matches {
        run.record(&HistoryCommand {
            index: command.index,
            line: command.line,
            command: command.text.clone(),
            urls: command.urls.clone(),
        })
        .from(file)
        .note(format!("line {}", command.line))
        .emit()?;
    }
    Ok(Some(history.matches.len()))
}

fn psreadline_files(run: &Run) -> Result<()> {
    let mut files = 0usize;
    let mut invalid = 0usize;
    let mut commands = 0usize;

    for file in run.inputs() {
        run.check_cancelled()?;
        match analyze_file(run, file, file.name(), file.name())? {
            Some(found) => {
                files += 1;
                commands += found;
            }
            None => invalid += 1,
        }
    }

    if run.inputs().is_empty() {
        run.warn(
            "INPUT_NOT_FOUND",
            "未选择 PowerShell 历史文件；请选择 ConsoleHost_history.txt 或使用检材分析器",
        )?;
    }
    run.set_summary(format!(
        "读取 {files} 份 PSReadLine 历史，共 {commands} 条含 URL 的命令；无法解析 {invalid} 份。历史文件没有可靠的执行时间，不生成时间线。"
    ));
    Ok(())
}

fn psreadline_evidence(run: &Run) -> Result<()> {
    let view = run.require_view()?;
    let roots = view.list("")?;
    let mut files = 0usize;
    let mut invalid = 0usize;
    let mut commands = 0usize;
    let mut volumes = 0usize;

    for root in roots {
        if !root.is_dir() || !component(&root.name) {
            continue;
        }
        run.check_cancelled()?;
        volumes += 1;
        let mut profiles = vec![String::new()];
        let users_path = format!("{}/Users", root.name);
        let users = view.list_or_empty(&users_path)?;
        if users.len() > MAX_USERS {
            run.warn(
                "USERS_LIMIT",
                format!(
                    "{users_path} 有 {} 个条目，超过 {MAX_USERS} 个上限；未枚举该卷的用户目录，仅检查卷根路径",
                    users.len()
                ),
            )?;
        } else {
            for user in users {
                if !user.is_dir() || user.deleted {
                    continue;
                }
                if !component(&user.name) {
                    run.warn(
                        "INVALID_PATH",
                        format!("{users_path}: 非法的用户目录名 {:?}", user.name),
                    )?;
                    continue;
                }
                profiles.push(format!("Users/{}", user.name));
            }
        }

        for profile in profiles {
            for relative in RELATIVE {
                run.check_cancelled()?;
                let path = if profile.is_empty() {
                    format!("{}/{}", root.name, relative)
                } else {
                    format!("{}/{}/{}", root.name, profile, relative)
                };
                let Some(node) = view.stat(&path)? else {
                    continue;
                };
                if !node.is_file() || node.deleted {
                    continue;
                }
                let Some(file) = view.open(&path)? else {
                    run.warn(
                        "FILE_DISAPPEARED",
                        format!("{path}: 列出后无法打开，未产生记录"),
                    )?;
                    invalid += 1;
                    continue;
                };
                match analyze_file(run, &file, &path, &path)? {
                    Some(found) => {
                        files += 1;
                        commands += found;
                    }
                    None => invalid += 1,
                }
            }
        }
    }

    if files == 0 {
        run.warn(
            "HISTORY_NOT_FOUND",
            format!(
                "在 {volumes} 个卷的标准用户目录中未找到 ConsoleHost_history.txt；自定义 HistorySavePath 与其他 host 的历史不在扫描范围"
            ),
        )?;
    } else {
        run.emit(&HistoryTotal {
            file_count: files,
            url_command_count: commands,
        })?;
    }
    run.set_summary(format!(
        "扫描 {volumes} 个卷，读取 {files} 份 PSReadLine 历史，共 {commands} 条含 URL 的命令；无法解析 {invalid} 份。不推断执行时间。"
    ));
    Ok(())
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.psreadline")
        .record::<HistoryFile>()
        .record::<HistoryCommand>()
        .record::<HistoryTotal>()
        .analyzer("psreadline_files", psreadline_files)
        .analyzer("psreadline_evidence", psreadline_evidence)
}

export_plugin!(plugin);
