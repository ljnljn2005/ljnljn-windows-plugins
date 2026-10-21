//! Windows Vista+ recycle-bin `$I` metadata (LPP v2).
//!
//! The file analyzer parses the `$I` file the user selected. The evidence
//! analyzer walks every volume of the evidence item, looks at
//! `$Recycle.Bin` and its first-level owner directories, and reports each
//! `$I` metadata record together with the presence of its `$R` companion.
//!
//! Parsing is unchanged from the LPP v1 plugin: strict v1/v2 header checks,
//! a complete absolute Windows path, a representable deletion FILETIME and
//! the size stored in `$I`. Malformed metadata is reported as a per-file
//! warning, never as a silent empty success; the deletion time is emitted as
//! a UTC `Timestamp` projected into the case timeline.

mod parser;

#[cfg(test)]
mod tests;

use lovelycarve_plugin::{export_plugin, Plugin, Record, Result, Run, Timestamp, View};

use crate::parser::{parse_i, Record as ParsedRecord, MAX_RECORD_BYTES};

/// Most volumes scanned in one evidence run.
const MAX_ROOTS: usize = 32;
/// Most first-level owner directories under one `$Recycle.Bin`.
const MAX_DIRECTORIES: usize = 256;
/// Most directory entries visited in one evidence run.
const MAX_ENTRIES: usize = 20_000;
/// Most `$I` candidates parsed in one evidence run.
const MAX_RECORDS: usize = 4096;

#[derive(Record)]
#[record(
    id = "windows.recyclebin.entry",
    label = "回收站记录",
    title = "{original_name}"
)]
struct RecycleEntry {
    #[field(label = "原始路径", kind = "path", key)]
    original_path: String,
    #[field(label = "原始文件名")]
    original_name: String,
    #[field(label = "原始大小", kind = "size")]
    original_size: u64,
    #[field(label = "删除时间（UTC）", timeline = "deleted")]
    deleted_at: Timestamp,
    #[field(label = "删除时间（FILETIME）")]
    deleted_filetime: u64,
    #[field(label = "$I 版本")]
    version: u64,
    #[field(
        label = "$R 状态",
        kind = "enum",
        choices = "not_checked_file_scope=未检查（单文件）,present_file=文件仍存在,present_directory=目录仍存在,missing=$R 缺失,unknown=无法确定"
    )]
    companion_state: String,
    #[field(label = "$R 路径", kind = "path")]
    companion_path: Option<String>,
    #[field(label = "$R 是否存在")]
    companion_present: Option<bool>,
    #[field(label = "$R 大小", kind = "size")]
    companion_size: Option<u64>,
    #[field(label = "大小一致")]
    size_matches: Option<bool>,
}

impl RecycleEntry {
    fn new(record: &ParsedRecord) -> Self {
        Self {
            original_path: record.original_path.clone(),
            original_name: record.original_name().to_owned(),
            original_size: record.original_size,
            deleted_at: deletion_time(record),
            deleted_filetime: record.deleted_filetime,
            version: record.version,
            companion_state: "unknown".to_owned(),
            companion_path: None,
            companion_present: None,
            companion_size: None,
            size_matches: None,
        }
    }
}

/// `$I` stores deletion as a 100 ns FILETIME; the parser already bounds it
/// to years 1601..9999, so the conversion cannot lose a value.
fn deletion_time(record: &ParsedRecord) -> Timestamp {
    let seconds = record.deleted_unix_nanos.div_euclid(1_000_000_000);
    let nanos = record.deleted_unix_nanos.rem_euclid(1_000_000_000);
    let seconds = i64::try_from(seconds).unwrap_or(0);
    Timestamp::from_unix_nanos(seconds, u32::try_from(nanos).unwrap_or(0))
}

fn is_i_file(name: &str) -> bool {
    name.len() > 2
        && name
            .get(..2)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("$I"))
}

/// A view path component the plugin is willing to join. Windows names never
/// contain a separator; a host that returns one is not trusted.
fn component(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains(['/', '\\'])
        && !name.chars().any(char::is_control)
}

/// The `$R` companion of an `$I` file: same directory, same suffix.
fn paired_path(path: &str) -> Option<String> {
    let (directory, name) = path.rsplit_once('/').unwrap_or(("", path));
    if !is_i_file(name) || !component(name) {
        return None;
    }
    let companion = format!("$R{}", &name[2..]);
    Some(if directory.is_empty() {
        companion
    } else {
        format!("{directory}/{companion}")
    })
}

fn recyclebin_files(run: &Run) -> Result<()> {
    let mut files = 0usize;
    let mut invalid = 0usize;
    let mut emitted = 0usize;

    for file in run.inputs() {
        run.check_cancelled()?;
        files += 1;
        let bytes = match file.read_all(MAX_RECORD_BYTES as u64) {
            Ok(bytes) => bytes,
            Err(error) => {
                invalid += 1;
                run.warn_file(file, &error.code, error.message)?;
                continue;
            }
        };
        let record = match parse_i(&bytes) {
            Ok(record) => record,
            Err(error) => {
                invalid += 1;
                run.warn_file(
                    file,
                    "INVALID_RECYCLE_METADATA",
                    format!("{}: {error}", file.name()),
                )?;
                continue;
            }
        };
        let mut entry = RecycleEntry::new(&record);
        entry.companion_state = "not_checked_file_scope".to_owned();
        run.record(&entry)
            .from(file)
            .at(0, file.size())
            .note(file.name())
            .emit()?;
        emitted += 1;
    }

    if files == 0 {
        run.warn(
            "INPUT_NOT_FOUND",
            "未选择 $I 元数据文件；请选择一个回收站 $I 文件或使用检材分析器",
        )?;
    }
    run.set_summary(format!(
        "解析 {files} 个 $I 文件，输出 {emitted} 条记录，损坏/不支持 {invalid} 个（单文件模式不检查 $R）"
    ));
    Ok(())
}

#[derive(Default)]
struct Counts {
    volumes: usize,
    entries: usize,
    candidates: usize,
    valid: usize,
    invalid: usize,
}

fn recyclebin_evidence(run: &Run) -> Result<()> {
    let view = run.require_view()?;
    let roots = view.list("")?;
    if roots.iter().filter(|node| node.is_dir()).count() > MAX_ROOTS {
        return Err(lovelycarve_plugin::Error::new(
            "RESOURCE_LIMIT",
            format!("检材卷数超过 {MAX_ROOTS} 个"),
        ));
    }
    let mut counts = Counts::default();
    for root in roots {
        if !root.is_dir() || !component(&root.name) {
            continue;
        }
        run.check_cancelled()?;
        counts.volumes += 1;
        let path = format!("{}/$Recycle.Bin", root.name);
        if !view.is_dir(&path)? {
            continue;
        }
        scan_directory(view, &path, true, run, &mut counts)?;
    }

    if counts.volumes == 0 {
        run.warn("NO_VOLUMES", "检材视图没有可扫描的卷")?;
    } else if counts.candidates == 0 {
        run.warn(
            "RECYCLE_BIN_NOT_FOUND",
            format!(
                "扫描 {} 个卷，未找到 $Recycle.Bin 下的 $I 元数据",
                counts.volumes
            ),
        )?;
    }
    run.set_summary(format!(
        "扫描 {} 个卷；$I 候选 {} 条，有效 {} 条，损坏/不支持 {} 条；只解析元数据并检查 $R 存在性，未恢复内容",
        counts.volumes, counts.candidates, counts.valid, counts.invalid
    ));
    Ok(())
}

fn scan_directory(
    view: &View,
    path: &str,
    descend: bool,
    run: &Run,
    counts: &mut Counts,
) -> Result<()> {
    run.check_cancelled()?;
    let nodes = view.list(path)?;
    counts.entries = counts
        .entries
        .checked_add(nodes.len())
        .ok_or_else(|| lovelycarve_plugin::Error::new("RESOURCE_LIMIT", "目录项计数溢出"))?;
    if counts.entries > MAX_ENTRIES {
        return Err(lovelycarve_plugin::Error::new(
            "RESOURCE_LIMIT",
            format!("回收站扫描超过 {MAX_ENTRIES} 个目录项"),
        ));
    }
    let mut directories = Vec::new();
    for node in nodes {
        run.check_cancelled()?;
        if !component(&node.name) {
            run.warn(
                "INVALID_PATH",
                format!("宿主返回了非法的回收站路径组件：{:?}", node.name),
            )?;
            continue;
        }
        if node.deleted || node.kind == lovelycarve_plugin::NodeKind::Link {
            continue;
        }
        let source = format!("{path}/{}", node.name);
        if node.is_dir() && descend {
            directories.push(source);
            if directories.len() > MAX_DIRECTORIES {
                return Err(lovelycarve_plugin::Error::new(
                    "RESOURCE_LIMIT",
                    format!("回收站扫描超过 {MAX_DIRECTORIES} 个所有者目录"),
                ));
            }
        } else if node.is_file() && is_i_file(&node.name) {
            counts.candidates += 1;
            if counts.candidates > MAX_RECORDS {
                return Err(lovelycarve_plugin::Error::new(
                    "RESOURCE_LIMIT",
                    format!("回收站扫描超过 {MAX_RECORDS} 条 $I 元数据"),
                ));
            }
            analyze_candidate(view, &source, run, counts)?;
        }
    }
    directories.sort();
    for directory in directories {
        scan_directory(view, &directory, false, run, counts)?;
    }
    Ok(())
}

fn analyze_candidate(view: &View, source: &str, run: &Run, counts: &mut Counts) -> Result<()> {
    let Some(file) = view.open(source)? else {
        counts.invalid += 1;
        run.warn(
            "FILE_DISAPPEARED",
            format!("{source}: 列出后无法打开，未产生记录"),
        )?;
        return Ok(());
    };
    let bytes = match file.read_all(MAX_RECORD_BYTES as u64) {
        Ok(bytes) => bytes,
        Err(error) => {
            counts.invalid += 1;
            run.warn_file(&file, &error.code, error.message)?;
            return Ok(());
        }
    };
    let parsed = match parse_i(&bytes) {
        Ok(parsed) => parsed,
        Err(error) => {
            counts.invalid += 1;
            run.warn_file(
                &file,
                "INVALID_RECYCLE_METADATA",
                format!("{source}: {error}"),
            )?;
            return Ok(());
        }
    };

    let mut entry = RecycleEntry::new(&parsed);
    let companion = paired_path(source);
    if let Some(companion) = &companion {
        entry.companion_path = Some(companion.clone());
    }
    match companion.as_deref() {
        Some(companion) => match view.stat(companion)? {
            Some(node) if !node.deleted && (node.is_file() || node.is_dir()) => {
                entry.companion_present = Some(true);
                if node.is_file() {
                    entry.companion_state = "present_file".to_owned();
                    entry.companion_size = Some(node.size);
                    entry.size_matches = Some(node.size == parsed.original_size);
                } else {
                    entry.companion_state = "present_directory".to_owned();
                }
            }
            _ => {
                entry.companion_state = "missing".to_owned();
                entry.companion_present = Some(false);
            }
        },
        None => {
            run.warn_file(
                &file,
                "INVALID_COMPANION_PATH",
                format!("{source}: 无法确定对应的 $R 路径"),
            )?;
        }
    }

    run.record(&entry)
        .from(&file)
        .at(0, file.size())
        .note(source)
        .emit()?;
    counts.valid += 1;
    Ok(())
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.recyclebin")
        .record::<RecycleEntry>()
        .analyzer("recyclebin_files", recyclebin_files)
        .analyzer("recyclebin_evidence", recyclebin_evidence)
}

export_plugin!(plugin);
