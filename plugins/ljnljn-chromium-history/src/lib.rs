//! Chromium (Chrome / Edge) History visits and downloads (LPP v2).
//!
//! One engine serves three analyzers: a system run over the declared
//! `User Data/*/History` inputs, an evidence run that resolves the same
//! inputs on every volume, and a file run over a selected History database.
//! Each profile is read as a private, immutable SQLite snapshot of the main
//! database; `-wal` / `-shm` sidecars are reported but never merged, so rows
//! still in the WAL are not part of the snapshot. Every record carries that
//! snapshot scope.
//!
//! Records are typed: profile status, per-profile and cross-profile URL and
//! title visit counts (`COUNT(visits.id)`, with `urls.visit_count` kept as a
//! separate declared counter), and the `downloads` table when present. The
//! source file of every record is attached, and cross-profile totals keep up
//! to 16 source references with an explicit profile count.

mod query;
#[cfg(test)]
mod tests;

use std::collections::BTreeMap;

use lovelycarve_plugin::{
    export_plugin, FileRef, Plugin, Record, Result, Run, SourceRef, Timestamp, View,
};

use crate::query::{
    chromium_time, limit, parse_database, Aggregate, DownloadRow, ProfileStats, Source,
    MAIN_ONLY_NOTE, MAX_DB_BYTES,
};

/// Most records one run may emit before failing loudly instead of
/// truncating.
const MAX_RECORDS: u64 = 10_000;
/// Most source references one cross-profile record carries.
const MAX_SOURCES: usize = 16;

#[derive(Record)]
#[record(id = "browser.profile", label = "浏览器配置", title = "{browser} / {profile}")]
struct ProfileRecord {
    #[field(label = "浏览器", key)]
    browser: String,
    #[field(label = "配置", key)]
    profile: String,
    #[field(label = "数据库路径", kind = "path")]
    path: String,
    #[field(
        label = "状态",
        kind = "enum",
        choices = "parsed=已解析,failed=解析失败"
    )]
    status: String,
    #[field(label = "URL 行数")]
    url_rows: i64,
    #[field(label = "访问次数")]
    visits: i64,
    #[field(label = "孤立访问行")]
    orphan_visits: i64,
    #[field(label = "下载记录数")]
    downloads: i64,
    #[field(label = "WAL 存在")]
    wal_present: Option<bool>,
    #[field(label = "SHM 存在")]
    shm_present: Option<bool>,
    #[field(label = "主库头为 WAL 模式")]
    wal_header: bool,
    #[field(
        label = "快照范围",
        kind = "enum",
        choices = "main_database_only=仅主库"
    )]
    snapshot_scope: String,
    #[field(label = "快照说明")]
    snapshot_note: String,
    #[field(label = "错误码")]
    error_code: Option<String>,
    #[field(label = "错误")]
    error: Option<String>,
}

#[derive(Record)]
#[record(
    id = "browser.url.profile",
    label = "各配置 URL 访问",
    title = "{url}"
)]
struct UrlProfileRecord {
    #[field(label = "浏览器", key)]
    browser: String,
    #[field(label = "配置", key)]
    profile: String,
    #[field(label = "URL", key)]
    url: String,
    #[field(label = "实际访问次数")]
    visits: i64,
    #[field(label = "urls.visit_count 汇总")]
    declared_visits: i64,
    #[field(label = "URL 行数")]
    url_rows: i64,
    #[field(label = "标题")]
    titles: Vec<String>,
    #[field(label = "首次访问", timeline = "visited")]
    first_visit: Option<Timestamp>,
    #[field(label = "末次访问", timeline = "visited")]
    last_visit: Option<Timestamp>,
}

#[derive(Record)]
#[record(
    id = "browser.url.total",
    label = "跨配置 URL 访问",
    title = "{url}"
)]
struct UrlTotalRecord {
    #[field(label = "URL", key)]
    url: String,
    #[field(label = "配置数")]
    profiles: i64,
    #[field(label = "浏览器")]
    browsers: Vec<String>,
    #[field(label = "实际访问次数")]
    visits: i64,
    #[field(label = "urls.visit_count 汇总")]
    declared_visits: i64,
    #[field(label = "URL 行数")]
    url_rows: i64,
    #[field(label = "标题")]
    titles: Vec<String>,
    #[field(label = "首次访问", timeline = "visited")]
    first_visit: Option<Timestamp>,
    #[field(label = "末次访问", timeline = "visited")]
    last_visit: Option<Timestamp>,
}

#[derive(Record)]
#[record(
    id = "browser.title.profile",
    label = "各配置标题访问",
    title = "{title}"
)]
struct TitleProfileRecord {
    #[field(label = "浏览器", key)]
    browser: String,
    #[field(label = "配置", key)]
    profile: String,
    #[field(label = "标题", key)]
    title: String,
    #[field(label = "实际访问次数")]
    visits: i64,
    #[field(label = "urls.visit_count 汇总")]
    declared_visits: i64,
    #[field(label = "URL 行数")]
    url_rows: i64,
    #[field(label = "URL")]
    urls: Vec<String>,
    #[field(label = "首次访问", timeline = "visited")]
    first_visit: Option<Timestamp>,
    #[field(label = "末次访问", timeline = "visited")]
    last_visit: Option<Timestamp>,
}

#[derive(Record)]
#[record(
    id = "browser.title.total",
    label = "跨配置标题访问",
    title = "{title}"
)]
struct TitleTotalRecord {
    #[field(label = "标题", key)]
    title: String,
    #[field(label = "配置数")]
    profiles: i64,
    #[field(label = "浏览器")]
    browsers: Vec<String>,
    #[field(label = "实际访问次数")]
    visits: i64,
    #[field(label = "urls.visit_count 汇总")]
    declared_visits: i64,
    #[field(label = "URL 行数")]
    url_rows: i64,
    #[field(label = "URL")]
    urls: Vec<String>,
    #[field(label = "首次访问", timeline = "visited")]
    first_visit: Option<Timestamp>,
    #[field(label = "末次访问", timeline = "visited")]
    last_visit: Option<Timestamp>,
}

#[derive(Record)]
#[record(id = "browser.download", label = "下载记录", title = "{target_path}")]
struct DownloadRecord {
    #[field(label = "浏览器", key)]
    browser: String,
    #[field(label = "配置", key)]
    profile: String,
    #[field(label = "下载 ID", key)]
    download_id: Option<i64>,
    #[field(label = "目标路径", kind = "path")]
    target_path: Option<String>,
    #[field(label = "来源页")]
    tab_url: Option<String>,
    #[field(label = "Referrer")]
    referrer: Option<String>,
    #[field(label = "站点")]
    site_url: Option<String>,
    #[field(label = "开始时间", timeline = "visited")]
    start_time: Option<Timestamp>,
    #[field(label = "已接收字节", kind = "size")]
    received_bytes: Option<u64>,
    #[field(label = "总字节", kind = "size")]
    total_bytes: Option<u64>,
    #[field(label = "状态码")]
    state: Option<i64>,
    #[field(
        label = "状态",
        kind = "enum",
        choices = "in_progress=进行中,complete=完成,cancelled=已取消,interrupted=已中断,unknown=未知"
    )]
    state_name: String,
    #[field(label = "危险类型码")]
    danger_type: Option<i64>,
    #[field(
        label = "危险类型",
        kind = "enum",
        choices = "not_dangerous=非危险,dangerous_file=危险文件,dangerous_url=危险地址,dangerous_content=危险内容,maybe_dangerous_content=可能危险,uncommon_content=少见内容,user_validated=用户确认,dangerous_host=危险主机,potentially_unwanted=潜在不受欢迎,unknown=未知"
    )]
    danger_name: String,
    #[field(label = "中断原因码")]
    interrupt_reason: Option<i64>,
    #[field(label = "MIME 类型")]
    mime_type: Option<String>,
    #[field(label = "原始 MIME 类型")]
    original_mime_type: Option<String>,
    #[field(label = "当前路径", kind = "path")]
    current_path: Option<String>,
}

#[derive(Default)]
struct Totals {
    urls: BTreeMap<String, Aggregate>,
    titles: BTreeMap<String, Aggregate>,
    sources: BTreeMap<String, SourceRef>,
}

fn history(run: &Run) -> Result<()> {
    let inputs = run.inputs();
    if inputs.is_empty() {
        run.warn(
            "INPUT_NOT_FOUND",
            "未找到声明的 Chromium History 输入（system/evidence 作用域按清单 inputs 解析；files 作用域需要选中 History 文件）",
        )?;
        run.set_summary("未找到可分析的 Chromium History 数据库");
        return Ok(());
    }

    let mut totals = Totals::default();
    let mut parsed = 0_usize;
    let mut failed = 0_usize;
    let mut downloads = 0_usize;
    for (index, file) in inputs.iter().enumerate() {
        run.check_cancelled()?;
        run.progress(
            index as u64,
            Some(inputs.len() as u64),
            Some(&format!("解析 {}", file.name())),
        )?;
        let (browser, profile) = describe(file);
        let (wal, shm) = sidecars(run, file)?;
        let source = Source {
            root: file.root().unwrap_or_default().to_owned(),
            path: file
                .root_path()
                .or_else(|| file.view_path())
                .unwrap_or_else(|| file.name())
                .to_owned(),
            browser: browser.clone(),
            profile: profile.clone(),
            wal,
            shm,
        };
        let parsed_profile = (|| -> Result<ProfileStats> {
            let bytes = file.read_all(MAX_DB_BYTES)?;
            parse_database(&bytes, &source, run.context())
        })();
        match parsed_profile {
            Ok(stats) => {
                parsed += 1;
                downloads += stats.downloads.len();
                emit_profile(
                    run,
                    file,
                    &source,
                    Some(&stats),
                    "parsed",
                    None,
                )?;
                emit_metrics(run, file, &source, &stats, &mut totals)?;
                emit_downloads(run, file, &source, &stats.downloads)?;
            }
            Err(error) if error.is_cancelled() || error.code == "RESOURCE_LIMIT" => {
                return Err(error);
            }
            Err(error) => {
                failed += 1;
                run.warn_file(
                    file,
                    "CHROMIUM_PROFILE_FAILED",
                    format!("{browser}/{profile}: {}", error.message),
                )?;
                emit_profile(
                    run,
                    file,
                    &source,
                    None,
                    "failed",
                    Some(&error),
                )?;
            }
        }
    }

    emit_totals(run, &totals)?;
    if parsed == 0 && failed > 0 {
        run.warn(
            "CHROMIUM_ALL_PROFILES_FAILED",
            format!("发现 {failed} 个 History 配置，但全部解析失败；详见各配置记录与运行告警"),
        )?;
    }
    run.set_summary(format!(
        "解析 {parsed} 个配置，失败 {failed} 个；URL 指标 {} 条，标题指标 {} 条，下载 {downloads} 条；{MAIN_ONLY_NOTE}",
        totals.urls.len(),
        totals.titles.len()
    ));
    Ok(())
}

fn describe(file: &FileRef) -> (String, String) {
    let path = file
        .root_path()
        .or_else(|| file.view_path())
        .unwrap_or_else(|| file.name());
    let segments: Vec<&str> = path
        .split(['/', '\\'])
        .filter(|segment| !segment.is_empty())
        .collect();
    let browser = if segments
        .iter()
        .any(|segment| segment.eq_ignore_ascii_case("Chrome"))
    {
        "Chrome"
    } else if segments
        .iter()
        .any(|segment| segment.eq_ignore_ascii_case("Edge"))
    {
        "Edge"
    } else {
        "Chromium"
    };
    let after = |wanted: &str| -> Option<String> {
        segments
            .iter()
            .position(|segment| segment.eq_ignore_ascii_case(wanted))
            .and_then(|index| segments.get(index + 1))
            .map(|segment| (*segment).to_owned())
    };
    let user = after("Users");
    let profile = after("User Data");
    match (user, profile) {
        (Some(user), Some(profile)) => (browser.to_owned(), format!("{user}/{profile}")),
        _ => (browser.to_owned(), file.name().to_owned()),
    }
}

fn sidecars(run: &Run, file: &FileRef) -> Result<(Option<bool>, Option<bool>)> {
    let Some(view) = run.view() else {
        return Ok((None, None));
    };
    let Some(path) = file.view_path() else {
        return Ok((None, None));
    };
    Ok((
        Some(sidecar(view, path, "-wal")?),
        Some(sidecar(view, path, "-shm")?),
    ))
}

fn sidecar(view: &View, path: &str, suffix: &str) -> Result<bool> {
    view.exists(&format!("{path}{suffix}"))
}

fn check_budget(run: &Run) -> Result<()> {
    if run.emitted() >= MAX_RECORDS {
        Err(limit(
            "Chromium result exceeds 10000 records; analyze individual History files",
        ))
    } else {
        Ok(())
    }
}

fn emit_profile(
    run: &Run,
    file: &FileRef,
    source: &Source,
    stats: Option<&ProfileStats>,
    status: &str,
    error: Option<&lovelycarve_plugin::Error>,
) -> Result<()> {
    check_budget(run)?;
    let record = ProfileRecord {
        browser: source.browser.clone(),
        profile: source.profile.clone(),
        path: source.path.clone(),
        status: status.to_owned(),
        url_rows: stats.map(|stats| stats.url_rows).unwrap_or_default(),
        visits: stats.map(|stats| stats.visits).unwrap_or_default(),
        orphan_visits: stats.map(|stats| stats.orphan_visits).unwrap_or_default(),
        downloads: stats.map(|stats| stats.downloads.len() as i64).unwrap_or_default(),
        wal_present: source.wal,
        shm_present: source.shm,
        wal_header: stats.map(|stats| stats.wal_header).unwrap_or_default(),
        snapshot_scope: "main_database_only".to_owned(),
        snapshot_note: MAIN_ONLY_NOTE.to_owned(),
        error_code: error.map(|error| error.code.clone()),
        error: error.map(|error| error.message.clone()),
    };
    run.record(&record).from(file).emit()
}

fn emit_metrics(
    run: &Run,
    file: &FileRef,
    source: &Source,
    stats: &ProfileStats,
    totals: &mut Totals,
) -> Result<()> {
    for (url, aggregate) in &stats.urls {
        check_budget(run)?;
        run.record(&UrlProfileRecord {
            browser: source.browser.clone(),
            profile: source.profile.clone(),
            url: url.clone(),
            visits: aggregate.visits,
            declared_visits: aggregate.declared,
            url_rows: aggregate.url_rows,
            titles: aggregate.titles.iter().cloned().collect(),
            first_visit: aggregate.first.and_then(chromium_time),
            last_visit: aggregate.last.and_then(chromium_time),
        })
        .from(file)
        .emit()?;
        totals
            .urls
            .entry(url.clone())
            .or_default()
            .merge(aggregate, &source.profile, &source.browser)?;
    }
    for (title, aggregate) in &stats.titles {
        check_budget(run)?;
        run.record(&TitleProfileRecord {
            browser: source.browser.clone(),
            profile: source.profile.clone(),
            title: title.clone(),
            visits: aggregate.visits,
            declared_visits: aggregate.declared,
            url_rows: aggregate.url_rows,
            urls: aggregate.urls.iter().cloned().collect(),
            first_visit: aggregate.first.and_then(chromium_time),
            last_visit: aggregate.last.and_then(chromium_time),
        })
        .from(file)
        .emit()?;
        totals
            .titles
            .entry(title.clone())
            .or_default()
            .merge(aggregate, &source.profile, &source.browser)?;
    }
    totals.sources.insert(source.key(), file.source());
    Ok(())
}

fn emit_downloads(
    run: &Run,
    file: &FileRef,
    source: &Source,
    downloads: &[DownloadRow],
) -> Result<()> {
    for download in downloads {
        check_budget(run)?;
        run.record(&DownloadRecord {
            browser: source.browser.clone(),
            profile: source.profile.clone(),
            download_id: download.id,
            target_path: download.target_path.clone(),
            tab_url: download.tab_url.clone(),
            referrer: download.referrer.clone(),
            site_url: download.site_url.clone(),
            start_time: download.start_time.and_then(chromium_time),
            received_bytes: download
                .received_bytes
                .and_then(|bytes| u64::try_from(bytes).ok()),
            total_bytes: download
                .total_bytes
                .and_then(|bytes| u64::try_from(bytes).ok()),
            state: download.state,
            state_name: download_state(download.state).to_owned(),
            danger_type: download.danger_type,
            danger_name: download_danger(download.danger_type).to_owned(),
            interrupt_reason: download.interrupt_reason,
            mime_type: download.mime_type.clone(),
            original_mime_type: download.original_mime_type.clone(),
            current_path: download.current_path.clone(),
        })
        .from(file)
        .note(
            download
                .id
                .map(|id| format!("downloads.id={id}"))
                .unwrap_or_else(|| "downloads".to_owned()),
        )
        .emit()?;
    }
    Ok(())
}

fn emit_totals(run: &Run, totals: &Totals) -> Result<()> {
    for (url, aggregate) in &totals.urls {
        check_budget(run)?;
        let mut emit = run.record(&UrlTotalRecord {
            url: url.clone(),
            profiles: aggregate.profiles.len() as i64,
            browsers: aggregate.browsers.iter().cloned().collect(),
            visits: aggregate.visits,
            declared_visits: aggregate.declared,
            url_rows: aggregate.url_rows,
            titles: aggregate.titles.iter().cloned().collect(),
            first_visit: aggregate.first.and_then(chromium_time),
            last_visit: aggregate.last.and_then(chromium_time),
        });
        for source in totals.sources.values().take(MAX_SOURCES) {
            emit = emit.source(source.clone());
        }
        emit.emit()?;
    }
    for (title, aggregate) in &totals.titles {
        check_budget(run)?;
        let mut emit = run.record(&TitleTotalRecord {
            title: title.clone(),
            profiles: aggregate.profiles.len() as i64,
            browsers: aggregate.browsers.iter().cloned().collect(),
            visits: aggregate.visits,
            declared_visits: aggregate.declared,
            url_rows: aggregate.url_rows,
            urls: aggregate.urls.iter().cloned().collect(),
            first_visit: aggregate.first.and_then(chromium_time),
            last_visit: aggregate.last.and_then(chromium_time),
        });
        for source in totals.sources.values().take(MAX_SOURCES) {
            emit = emit.source(source.clone());
        }
        emit.emit()?;
    }
    Ok(())
}

fn download_state(state: Option<i64>) -> &'static str {
    match state {
        Some(0) => "in_progress",
        Some(1) => "complete",
        Some(2) => "cancelled",
        Some(3) => "interrupted",
        _ => "unknown",
    }
}

fn download_danger(danger: Option<i64>) -> &'static str {
    match danger {
        Some(0) => "not_dangerous",
        Some(1) => "dangerous_file",
        Some(2) => "dangerous_url",
        Some(3) => "dangerous_content",
        Some(4) => "maybe_dangerous_content",
        Some(5) => "uncommon_content",
        Some(6) => "user_validated",
        Some(7) => "dangerous_host",
        Some(8) => "potentially_unwanted",
        _ => "unknown",
    }
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.chromium-history")
        .record::<ProfileRecord>()
        .record::<UrlProfileRecord>()
        .record::<UrlTotalRecord>()
        .record::<TitleProfileRecord>()
        .record::<TitleTotalRecord>()
        .record::<DownloadRecord>()
        .analyzer("history", history)
        .analyzer("history_evidence", history)
        .analyzer("history_file", history)
}

export_plugin!(plugin);
