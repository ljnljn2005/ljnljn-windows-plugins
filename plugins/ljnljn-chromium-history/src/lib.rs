//! Read-only, main-database-only Chrome/Edge profile history statistics.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use lovelycarve_plugin::{
    export_plugin, AnalysisResult, Artifact, Attributes, Error, Evidence, EvidenceAnalyzer,
    EvidenceNode, EvidenceVolume, File, FileAnalyzer, Plugin, Result, ResultColumn, ResultNode,
    Value,
};
use rusqlite::{Connection, OpenFlags};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const MAX_DB_BYTES: u64 = 64 * 1024 * 1024;
const MAX_URL_ROWS: i64 = 100_000;
const MAX_VISITS: i64 = 5_000_000;
const MAX_PROFILES: usize = 256;
const MAX_RESULTS: usize = 10_000;
const MAX_PROFILE_TEXT_BYTES: usize = 1024 * 1024;
const SQL_BUDGET: Duration = Duration::from_secs(30);
const METHOD_SOURCE: &str = "wiki:writeups/PGS2025Final.md#04-3";
const MAIN_ONLY: &str = "仅统计主 History 数据库；WAL/SHM 未合并，可能遗漏尚在 WAL 中的访问。标题取 urls.title 当前值，不代表每次访问时的标题。";

#[derive(Clone, Debug)]
struct Source {
    root: String,
    path: String,
    browser: String,
    profile: String,
    wal: Option<bool>,
    shm: Option<bool>,
}

impl Source {
    fn key(&self) -> String {
        format!("{}:{}", self.root, self.path)
    }

    fn value(&self) -> Value {
        Value::Map(vec![
            ("root".into(), self.root.clone().into()),
            ("path".into(), self.path.clone().into()),
            ("browser".into(), self.browser.clone().into()),
            ("profile".into(), self.profile.clone().into()),
        ])
    }

    fn attributes(&self) -> Attributes {
        let mut attrs = common_attributes();
        attrs.insert("source.root", self.root.clone());
        attrs.insert("source.path", self.path.clone());
        attrs.insert("browser.name", self.browser.clone());
        attrs.insert("browser.profile", self.profile.clone());
        attrs.insert("browser.sidecars_checked", self.wal.is_some());
        attrs.insert_optional("browser.wal_present", self.wal);
        attrs.insert_optional("browser.shm_present", self.shm);
        attrs
    }
}

#[derive(Clone, Debug, Default)]
struct Aggregate {
    visits: i64,
    declared: i64,
    url_rows: i64,
    first: Option<i64>,
    last: Option<i64>,
    titles: BTreeSet<String>,
    urls: BTreeSet<String>,
    sources: BTreeSet<String>,
}

impl Aggregate {
    fn merge(&mut self, other: &Self) -> Result<()> {
        self.visits = self
            .visits
            .checked_add(other.visits)
            .ok_or_else(|| db_error("visit count overflow"))?;
        self.declared = self
            .declared
            .checked_add(other.declared)
            .ok_or_else(|| db_error("declared visit count overflow"))?;
        self.url_rows = self
            .url_rows
            .checked_add(other.url_rows)
            .ok_or_else(|| db_error("URL row count overflow"))?;
        self.first = match (self.first, other.first) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        };
        self.last = match (self.last, other.last) {
            (Some(a), Some(b)) => Some(a.max(b)),
            (a, b) => a.or(b),
        };
        self.titles.extend(other.titles.iter().cloned());
        self.urls.extend(other.urls.iter().cloned());
        self.sources.extend(other.sources.iter().cloned());
        Ok(())
    }
}

#[derive(Debug, Default)]
struct ProfileStats {
    urls: BTreeMap<String, Aggregate>,
    titles: BTreeMap<String, Aggregate>,
    url_rows: i64,
    visits: i64,
    orphan_visits: i64,
    wal_header: bool,
}

fn db_error(error: impl std::fmt::Display) -> Error {
    Error::new("CHROMIUM_DATABASE_ERROR", error.to_string())
}

fn limit(message: impl Into<String>) -> Error {
    Error::new("RESOURCE_LIMIT", message)
}

/// A create-new, private temporary copy, never a path into the evidence.
struct Snapshot(PathBuf);

impl Snapshot {
    fn create(bytes: &[u8]) -> Result<Self> {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(db_error)?
            .as_nanos();
        for _ in 0..20 {
            let path = std::env::temp_dir().join(format!(
                "ljnljn-chromium-{}-{nonce}-{}.sqlite",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            let mut options = OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&path) {
                Ok(mut file) => {
                    let snapshot = Self(path);
                    file.write_all(bytes).map_err(db_error)?;
                    file.flush().map_err(db_error)?;
                    return Ok(snapshot);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(db_error(error)),
            }
        }
        Err(db_error("cannot allocate a unique temporary snapshot"))
    }

    fn uri(&self) -> Result<String> {
        let path = self
            .0
            .to_str()
            .ok_or_else(|| db_error("non-Unicode temp path"))?;
        let mut uri = String::from("file:");
        for byte in path.replace('\\', "/").bytes() {
            if byte.is_ascii_alphanumeric() || b"/-_.:".contains(&byte) {
                uri.push(byte as char);
            } else {
                uri.push_str(&format!("%{byte:02X}"));
            }
        }
        uri.push_str("?mode=ro&immutable=1");
        Ok(uri)
    }
}

impl Drop for Snapshot {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

/// Poll cancellation from inside SQLite, including COUNT and the first JOIN step.
struct SqlGuard {
    check: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    started: Instant,
    budget: Duration,
    interrupted: Arc<Mutex<Option<Error>>>,
}

impl SqlGuard {
    fn install(
        conn: &Connection,
        check: impl Fn() -> Result<()> + Send + Sync + 'static,
        budget: Duration,
    ) -> Self {
        let guard = Self {
            check: Arc::new(check),
            started: Instant::now(),
            budget,
            interrupted: Arc::new(Mutex::new(None)),
        };
        let check = guard.check.clone();
        let interrupted = guard.interrupted.clone();
        let started = guard.started;
        conn.progress_handler(
            10_000,
            Some(move || {
                let error = check().err().or_else(|| {
                    (started.elapsed() >= budget).then(|| {
                        limit("SQLite exceeded its query time budget (30 seconds in production)")
                    })
                });
                if let Some(error) = error {
                    *interrupted.lock().unwrap_or_else(|p| p.into_inner()) = Some(error);
                    true
                } else {
                    false
                }
            }),
        );
        guard
    }

    fn check(&self) -> Result<()> {
        (self.check)()?;
        if self.started.elapsed() >= self.budget {
            return Err(limit(
                "SQLite exceeded its query time budget (30 seconds in production)",
            ));
        }
        Ok(())
    }

    fn error(&self, error: rusqlite::Error) -> Error {
        self.interrupted
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
            .unwrap_or_else(|| db_error(error))
    }
}

fn parse_database(
    bytes: &[u8],
    source: &Source,
    check: impl Fn() -> Result<()> + Send + Sync + 'static,
) -> Result<ProfileStats> {
    check()?;
    if bytes.len() as u64 > MAX_DB_BYTES {
        return Err(limit("History database exceeds 64 MiB"));
    }
    if bytes.len() < 100 || &bytes[..16] != b"SQLite format 3\0" {
        return Err(db_error("not a SQLite3 main database"));
    }
    let snapshot = Snapshot::create(bytes)?;
    let conn = Connection::open_with_flags(
        snapshot.uri()?,
        OpenFlags::SQLITE_OPEN_READ_ONLY
            | OpenFlags::SQLITE_OPEN_URI
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(db_error)?;
    let guard = SqlGuard::install(&conn, check, SQL_BUDGET);
    let sql_error = |error| guard.error(error);
    conn.execute_batch(
        "PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;",
    )
    .map_err(sql_error)?;
    for table in ["urls", "visits"] {
        let exists: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?1",
                [table],
                |row| row.get(0),
            )
            .map_err(sql_error)?;
        if exists != 1 {
            return Err(db_error(format!(
                "required Chromium table missing: {table}"
            )));
        }
    }
    let url_rows: i64 = conn
        .query_row("SELECT COUNT(*) FROM urls", [], |row| row.get(0))
        .map_err(sql_error)?;
    let visits: i64 = conn
        .query_row("SELECT COUNT(*) FROM visits", [], |row| row.get(0))
        .map_err(sql_error)?;
    if url_rows > MAX_URL_ROWS || visits > MAX_VISITS {
        return Err(limit(
            "History exceeds 100000 URL rows / 5000000 visit rows",
        ));
    }
    let valid_ids: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT id) FROM urls WHERE typeof(id)='integer'",
            [],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if valid_ids != url_rows {
        return Err(db_error("urls.id must contain unique integer identifiers"));
    }
    let valid_visits: i64 = conn
        .query_row(
            "SELECT COUNT(DISTINCT id) FROM visits WHERE typeof(id)='integer'",
            [],
            |row| row.get(0),
        )
        .map_err(sql_error)?;
    if valid_visits != visits {
        return Err(db_error(
            "visits.id must contain unique integer identifiers",
        ));
    }
    guard.check()?;
    let mut stats = ProfileStats {
        url_rows,
        visits,
        wal_header: bytes[18] == 2 || bytes[19] == 2,
        ..ProfileStats::default()
    };
    let mut statement = conn
        .prepare(
            "SELECT u.id, u.url, COALESCE(u.title,''), COALESCE(u.visit_count,0),
                COUNT(v.id), MIN(NULLIF(v.visit_time,0)), MAX(NULLIF(v.visit_time,0))
         FROM urls AS u LEFT JOIN visits AS v ON v.url=u.id GROUP BY u.id",
        )
        .map_err(sql_error)?;
    let mut rows = statement.query([]).map_err(sql_error)?;
    let mut joined_visits = 0_i64;
    let mut processed = 0;
    let mut text_bytes = 0_usize;
    while let Some(row) = rows.next().map_err(sql_error)? {
        processed += 1;
        if processed % 128 == 0 {
            guard.check()?;
        }
        let url: String = row.get(1).map_err(db_error)?;
        let title: String = row.get(2).map_err(db_error)?;
        if url.len() > 16_384 || title.len() > 16_384 {
            return Err(limit("URL or title exceeds 16384 UTF-8 bytes"));
        }
        text_bytes += url.len() + title.len();
        if text_bytes > MAX_PROFILE_TEXT_BYTES {
            return Err(limit(
                "History URL/title text exceeds 1 MiB per-profile processing budget",
            ));
        }
        let declared: i64 = row.get(3).map_err(db_error)?;
        let count: i64 = row.get(4).map_err(db_error)?;
        if declared < 0 {
            return Err(db_error("negative urls.visit_count"));
        }
        joined_visits += count;
        let aggregate = Aggregate {
            visits: count,
            declared,
            url_rows: 1,
            first: row.get(5).map_err(db_error)?,
            last: row.get(6).map_err(db_error)?,
            titles: BTreeSet::from([title.clone()]),
            urls: BTreeSet::from([url.clone()]),
            sources: BTreeSet::from([source.key()]),
        };
        stats.urls.entry(url).or_default().merge(&aggregate)?;
        stats.titles.entry(title).or_default().merge(&aggregate)?;
        // Each metric produces a per-profile and a cross-profile record.
        if 1 + 2 * (stats.urls.len() + stats.titles.len()) > MAX_RESULTS {
            return Err(limit("History profile alone exceeds 10000 result items"));
        }
    }
    stats.orphan_visits = visits - joined_visits;
    if stats.orphan_visits < 0 {
        return Err(db_error("invalid visits / urls join cardinality"));
    }
    guard.check()?;
    Ok(stats)
}

fn chromium_time(micros: i64) -> Option<String> {
    if micros <= 0 {
        return None;
    }
    let nanos = (i128::from(micros) - 11_644_473_600_000_000_i128) * 1000;
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .ok()?
        .format(&Rfc3339)
        .ok()
}

fn strings(values: &BTreeSet<String>) -> Value {
    Value::Array(values.iter().cloned().map(Value::from).collect())
}

fn common_attributes() -> Attributes {
    let mut attrs = Attributes::new();
    attrs.insert("method.source", METHOD_SOURCE);
    attrs.insert("browser.snapshot_scope", "main_database_only");
    attrs.insert("browser.warning", MAIN_ONLY);
    attrs.insert(
        "browser.count_basis",
        "COUNT(visits.id) joined on visits.url=urls.id",
    );
    attrs.insert(
        "browser.title_basis",
        "current urls.title; historic titles unavailable",
    );
    attrs
}

fn metric_artifact(
    kind: &str,
    key: &str,
    aggregate: &Aggregate,
    mut attrs: Attributes,
) -> Artifact {
    attrs.insert("browser.visits_count", aggregate.visits);
    attrs.insert("browser.declared_visit_count", aggregate.declared);
    attrs.insert("browser.url_row_count", aggregate.url_rows);
    attrs.insert("browser.profile_count", aggregate.sources.len() as u64);
    attrs.insert("browser.titles", strings(&aggregate.titles));
    attrs.insert("browser.urls", strings(&aggregate.urls));
    attrs.insert_optional("browser.first_visit_raw", aggregate.first);
    attrs.insert_optional("browser.last_visit_raw", aggregate.last);
    attrs.insert_optional(
        "browser.first_visit_utc",
        aggregate.first.and_then(chromium_time),
    );
    attrs.insert_optional(
        "browser.last_visit_utc",
        aggregate.last.and_then(chromium_time),
    );
    attrs.insert(
        if kind.contains(".url.") {
            "browser.url"
        } else {
            "browser.title"
        },
        key,
    );
    Artifact {
        artifact_type: kind.into(),
        title: if key.is_empty() {
            "（空标题）".into()
        } else {
            key.into()
        },
        value: Some(aggregate.visits.into()),
        attributes: attrs,
    }
}

#[derive(Default)]
struct Collection {
    artifacts: Vec<Artifact>,
    urls: BTreeMap<String, Aggregate>,
    titles: BTreeMap<String, Aggregate>,
    sources: BTreeMap<String, Source>,
    parsed: usize,
    failed: usize,
}

impl Collection {
    fn add(&mut self, source: Source, stats: ProfileStats) -> Result<()> {
        self.parsed += 1;
        let mut attrs = source.attributes();
        attrs.insert("browser.status", "parsed");
        attrs.insert("browser.url_row_count", stats.url_rows);
        attrs.insert("browser.visits_count", stats.visits);
        attrs.insert("browser.orphan_visits_count", stats.orphan_visits);
        attrs.insert("browser.wal_header", stats.wal_header);
        self.artifacts.push(Artifact {
            artifact_type: "browser.profile".into(),
            title: source.key(),
            value: None,
            attributes: attrs,
        });
        for (kind, rows, globals) in [
            ("browser.url.profile", &stats.urls, &mut self.urls),
            ("browser.title.profile", &stats.titles, &mut self.titles),
        ] {
            for (key, aggregate) in rows {
                self.artifacts
                    .push(metric_artifact(kind, key, aggregate, source.attributes()));
                globals.entry(key.clone()).or_default().merge(aggregate)?;
            }
        }
        self.sources.insert(source.key(), source);
        self.check_budget()
    }

    fn failed(&mut self, source: Source, error: &Error) {
        self.failed += 1;
        let mut attrs = source.attributes();
        attrs.insert("browser.status", "failed");
        attrs.insert("browser.error_code", error.code.clone());
        attrs.insert("browser.error", error.message.clone());
        self.artifacts.push(Artifact {
            artifact_type: "browser.profile".into(),
            title: source.key(),
            value: None,
            attributes: attrs,
        });
    }

    fn check_budget(&self) -> Result<()> {
        if self.artifacts.len() + self.urls.len() + self.titles.len() > MAX_RESULTS {
            Err(limit(
                "Chromium result exceeds 10000 items; analyze individual History files",
            ))
        } else {
            Ok(())
        }
    }

    fn finish(mut self) -> Result<AnalysisResult> {
        if self.parsed == 0 {
            if self.failed == 0 {
                return Err(Error::not_found("No Chrome/Edge History in standard Windows User Data profile paths; select an exported History with the file analyzer"));
            }
            let first = self
                .artifacts
                .first()
                .map(|artifact| {
                    format!(
                        "{}: {}",
                        artifact.title,
                        artifact
                            .attributes
                            .get("browser.error")
                            .and_then(Value::as_str)
                            .unwrap_or("parse failed")
                    )
                })
                .unwrap_or_default();
            return Err(Error::new(
                "CHROMIUM_ALL_PROFILES_FAILED",
                format!(
                    "Found {} History profiles but none parsed; first failure: {first}",
                    self.failed
                ),
            ));
        }
        self.check_budget()?;
        let partial = self.failed > 0;
        for artifact in &mut self.artifacts {
            artifact
                .attributes
                .insert("browser.partial_profiles", partial);
        }
        for (kind, rows) in [
            ("browser.url.total", &self.urls),
            ("browser.title.total", &self.titles),
        ] {
            for (key, aggregate) in rows {
                let mut attrs = common_attributes();
                attrs.insert("browser.partial_profiles", partial);
                attrs.insert(
                    "source.profiles",
                    Value::Array(
                        aggregate
                            .sources
                            .iter()
                            .filter_map(|key| self.sources.get(key))
                            .map(Source::value)
                            .collect(),
                    ),
                );
                self.artifacts
                    .push(metric_artifact(kind, key, aggregate, attrs));
            }
        }
        let result = AnalysisResult {
            summary: Some(format!(
                "解析 {} 个配置，失败 {} 个；{}{}",
                self.parsed,
                self.failed,
                if partial {
                    "跨配置统计为部分结果。"
                } else {
                    ""
                },
                MAIN_ONLY
            )),
            nodes: result_nodes(),
            artifacts: self.artifacts,
            ..AnalysisResult::default()
        };
        // Leave room for the LPP envelope below the host's 8 MiB frame limit.
        if lovelycarve_plugin::value::encode(&result.to_value())?.len() > 7 * 1024 * 1024 {
            return Err(limit(
                "Chromium encoded result exceeds 7 MiB; analyze individual History files",
            ));
        }
        Ok(result)
    }
}

fn result_nodes() -> Vec<ResultNode> {
    [
        ("browser.profile", "配置来源与解析状态"),
        ("browser.url.profile", "各配置 URL 访问次数"),
        ("browser.title.profile", "各配置标题访问次数"),
        ("browser.url.total", "跨配置 URL 访问次数"),
        ("browser.title.total", "跨配置标题访问次数"),
    ]
    .into_iter()
    .map(|(kind, name)| ResultNode {
        node_type: kind.into(),
        name: name.into(),
        columns: [
            ("browser.visits_count", "实际 visits 行数"),
            ("browser.declared_visit_count", "urls.visit_count 汇总"),
            ("browser.profile", "配置"),
            ("browser.first_visit_utc", "首次访问 UTC"),
            ("browser.last_visit_utc", "末次访问 UTC"),
            ("source.path", "来源"),
            ("browser.status", "解析状态"),
        ]
        .into_iter()
        .map(|(key, label)| ResultColumn {
            key: key.into(),
            label: label.into(),
        })
        .collect(),
    })
    .collect()
}

fn optional_list(volume: &EvidenceVolume, path: &str) -> Result<Vec<EvidenceNode>> {
    match volume.stat(path)? {
        Some(node) if node.is_dir() && !node.deleted => volume.list(path),
        _ => Ok(Vec::new()),
    }
}

struct ChromiumHistory;

impl EvidenceAnalyzer for ChromiumHistory {
    fn analyzer(&self) -> &str {
        "ljnljn.chromium-history"
    }

    fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult> {
        let mut collection = Collection::default();
        let mut discovered = 0;
        for root in evidence.roots()? {
            let volume = evidence.volume(&root.root_id);
            for user in optional_list(&volume, "Users")? {
                if !user.is_dir()
                    || user.deleted
                    || user.name.contains(['/', '\\'])
                    || user.name == "."
                    || user.name == ".."
                {
                    continue;
                }
                for (browser, base) in [
                    ("Chrome", "Google/Chrome/User Data"),
                    ("Edge", "Microsoft/Edge/User Data"),
                ] {
                    let base = format!("Users/{}/AppData/Local/{base}", user.name);
                    for profile in optional_list(&volume, &base)? {
                        evidence.context().check_cancelled()?;
                        if !profile.is_dir()
                            || profile.deleted
                            || profile.name.contains(['/', '\\'])
                            || profile.name == "."
                            || profile.name == ".."
                        {
                            continue;
                        }
                        let path = format!("{base}/{}/History", profile.name);
                        let Some(node) = volume.stat(&path)? else {
                            continue;
                        };
                        if !node.is_file() || node.deleted {
                            continue;
                        }
                        discovered += 1;
                        if discovered > MAX_PROFILES {
                            return Err(limit("more than 256 Chromium profiles"));
                        }
                        let source = Source {
                            root: root.root_id.clone(),
                            path: path.clone(),
                            browser: browser.into(),
                            profile: format!("{}/{}", user.name, profile.name),
                            wal: Some(volume.exists(&format!("{path}-wal"))?),
                            shm: Some(volume.exists(&format!("{path}-shm"))?),
                        };
                        evidence.progress(
                            discovered as u64,
                            None,
                            Some(&format!("读取 {browser} {}", source.profile)),
                        )?;
                        let parsed = (|| {
                            if node.size > MAX_DB_BYTES {
                                return Err(limit("History database exceeds 64 MiB"));
                            }
                            let bytes = volume.read(&path, 0, Some(node.size))?;
                            if bytes.len() as u64 != node.size {
                                return Err(Error::new(
                                    "SHORT_READ",
                                    "History read returned fewer bytes than stat",
                                ));
                            }
                            let context = evidence.context().clone();
                            parse_database(&bytes, &source, move || context.check_cancelled())
                        })();
                        match parsed {
                            Ok(stats) => collection.add(source, stats)?,
                            Err(error)
                                if error.is_cancelled() || error.code == "RESOURCE_LIMIT" =>
                            {
                                return Err(error)
                            }
                            Err(error) => collection.failed(source, &error),
                        }
                    }
                }
            }
        }
        collection.finish()
    }
}

struct HistoryFile;

impl FileAnalyzer for HistoryFile {
    fn analyzer(&self) -> &str {
        "ljnljn.chromium-history.file"
    }

    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        if file.size() > MAX_DB_BYTES {
            return Err(limit("History database exceeds 64 MiB"));
        }
        let source = Source {
            root: String::new(),
            path: file.name().into(),
            browser: "Chromium (single file)".into(),
            profile: "selected file; siblings unavailable".into(),
            wal: None,
            shm: None,
        };
        let bytes = file.read(0, file.size() as usize)?;
        if bytes.len() as u64 != file.size() {
            return Err(Error::new(
                "SHORT_READ",
                "History file read returned fewer bytes than stat",
            ));
        }
        let context = file.context().clone();
        let stats = parse_database(&bytes, &source, move || context.check_cancelled())?;
        let mut collection = Collection::default();
        collection.add(source, stats)?;
        collection.finish()
    }
}

fn plugin() -> Plugin {
    Plugin::new(
        "org.ljnljn.chromium-history",
        "Chromium 多配置历史统计",
        env!("CARGO_PKG_VERSION"),
    )
    .evidence_analyzer(ChromiumHistory)
    .file_analyzer(HistoryFile)
}

export_plugin!(plugin);

#[cfg(test)]
mod tests {
    use super::*;
    use rusqlite::DatabaseName;

    const EPOCH: i64 = 11_644_473_600_000_000;

    fn source(profile: &str) -> Source {
        Source {
            root: "part:0".into(),
            path: format!("Users/test/AppData/Local/Google/Chrome/User Data/{profile}/History"),
            browser: "Chrome".into(),
            profile: profile.into(),
            wal: Some(false),
            shm: Some(false),
        }
    }

    fn database(sql: &str) -> Vec<u8> {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER);
             CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
             CREATE INDEX visits_url ON visits(url);",
        ).unwrap();
        conn.execute_batch(sql).unwrap();
        let bytes = conn.serialize(DatabaseName::Main).unwrap().to_vec();
        bytes
    }

    fn fixture() -> Vec<u8> {
        database(&format!(
            "INSERT INTO urls VALUES(1,'https://a.example.invalid/','Portal',99);
             INSERT INTO urls VALUES(2,'https://b.example.invalid/','Portal',7);
             INSERT INTO urls VALUES(3,'https://a.example.invalid/','Other',5);
             INSERT INTO urls VALUES(4,'https://unused.example.invalid/',NULL,12);
             INSERT INTO visits VALUES(1,1,{}),(2,1,{}),(3,2,{}),(4,3,{}),(5,999,{});",
            EPOCH + 1_234_567,
            EPOCH + 2_000_000,
            EPOCH + 3_000_000,
            EPOCH + 4_000_000,
            EPOCH + 5_000_000,
        ))
    }

    fn parse(bytes: &[u8]) -> ProfileStats {
        parse_database(bytes, &source("Default"), || Ok(())).unwrap()
    }

    fn int(attrs: &Attributes, key: &str) -> i64 {
        attrs.get(key).unwrap().as_i64().unwrap()
    }

    #[test]
    fn joins_real_visits_and_separates_url_title_and_declared_counts() {
        let stats = parse(&fixture());
        assert_eq!(stats.url_rows, 4);
        assert_eq!(stats.visits, 5);
        assert_eq!(stats.orphan_visits, 1);
        let a = &stats.urls["https://a.example.invalid/"];
        assert_eq!((a.visits, a.declared, a.url_rows), (3, 104, 2));
        assert_eq!(a.titles, BTreeSet::from(["Other".into(), "Portal".into()]));
        assert_eq!(a.first, Some(EPOCH + 1_234_567));
        assert_eq!(a.last, Some(EPOCH + 4_000_000));
        assert_eq!(stats.titles["Portal"].visits, 3);
        assert_eq!(stats.titles["Portal"].declared, 106);
        assert_eq!(stats.titles["Other"].visits, 1);
        assert_eq!(stats.titles[""].visits, 0);
        assert_eq!(stats.urls["https://unused.example.invalid/"].first, None);
    }

    #[test]
    fn cross_profile_totals_retain_all_profile_sources() {
        let second = database(&format!(
            "INSERT INTO urls VALUES(1,'https://a.example.invalid/','Portal',4),(2,'https://c.example.invalid/','Portal',20);
             INSERT INTO visits VALUES(1,1,{}),(2,2,{});", EPOCH + 6_000_000, EPOCH + 7_000_000,
        ));
        let one = source("Default");
        let mut two = source("WorkProfile");
        two.browser = "Edge".into();
        two.path = two.path.replace("Google/Chrome", "Microsoft/Edge");
        let mut collection = Collection::default();
        collection
            .add(
                one.clone(),
                parse_database(&fixture(), &one, || Ok(())).unwrap(),
            )
            .unwrap();
        collection
            .add(
                two.clone(),
                parse_database(&second, &two, || Ok(())).unwrap(),
            )
            .unwrap();
        let result = collection.finish().unwrap();
        let a = result
            .artifacts
            .iter()
            .find(|a| {
                a.artifact_type == "browser.url.total" && a.title == "https://a.example.invalid/"
            })
            .unwrap();
        assert_eq!(int(&a.attributes, "browser.visits_count"), 4);
        assert_eq!(int(&a.attributes, "browser.declared_visit_count"), 108);
        assert_eq!(int(&a.attributes, "browser.profile_count"), 2);
        let sources = a
            .attributes
            .get("source.profiles")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(sources.len(), 2);
        let paths = sources
            .iter()
            .map(|s| lovelycarve_plugin::value::required_str(s, "path").unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            paths,
            BTreeSet::from([one.path.as_str(), two.path.as_str()])
        );
        let portal = result
            .artifacts
            .iter()
            .find(|a| a.artifact_type == "browser.title.total" && a.title == "Portal")
            .unwrap();
        assert_eq!(int(&portal.attributes, "browser.visits_count"), 5);
        assert!(result.summary.unwrap().contains("WAL/SHM 未合并"));
    }

    #[test]
    fn chromium_microseconds_convert_to_utc_without_losing_precision() {
        assert_eq!(chromium_time(EPOCH), Some("1970-01-01T00:00:00Z".into()));
        assert_eq!(
            chromium_time(EPOCH + 1_234_567),
            Some("1970-01-01T00:00:01.234567Z".into())
        );
        assert_eq!(
            chromium_time(EPOCH - 1),
            Some("1969-12-31T23:59:59.999999Z".into())
        );
        assert_eq!(chromium_time(1), Some("1601-01-01T00:00:00.000001Z".into()));
        assert_eq!(chromium_time(0), None);
        assert_eq!(chromium_time(-1), None);
        assert_eq!(chromium_time(i64::MAX), None);
    }

    #[test]
    fn immutable_wal_snapshot_omits_uncheckpointed_rows_and_declares_it() {
        let snapshot = Snapshot::create(&database("")).unwrap();
        let writer = Connection::open(&snapshot.0).unwrap();
        writer
            .execute_batch(&format!(
                "PRAGMA journal_mode=WAL;
             INSERT INTO urls VALUES(1,'https://wal.example.invalid/','WAL test',8);
             INSERT INTO visits VALUES(1,1,{EPOCH});
             PRAGMA wal_checkpoint(TRUNCATE);
             INSERT INTO visits VALUES(2,1,{});",
                EPOCH + 1_000_000,
            ))
            .unwrap();
        assert!(snapshot.0.with_extension("sqlite-wal").exists());
        let bytes = fs::read(&snapshot.0).unwrap();
        let before = bytes.clone();
        let stats = parse(&bytes);
        assert!(stats.wal_header);
        assert_eq!(stats.visits, 1);
        assert_eq!(
            writer
                .query_row("SELECT COUNT(*) FROM visits", [], |r| r.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(bytes, before);
        let mut known_wal = source("Default");
        known_wal.wal = Some(true);
        known_wal.shm = Some(true);
        let mut collection = Collection::default();
        collection.add(known_wal, stats).unwrap();
        let result = collection.finish().unwrap();
        assert!(result.artifacts.iter().all(|a| a
            .attributes
            .get("browser.snapshot_scope")
            .unwrap()
            .as_str()
            == Some("main_database_only")));
        let profile = result
            .artifacts
            .iter()
            .find(|a| a.artifact_type == "browser.profile")
            .unwrap();
        assert_eq!(
            profile
                .attributes
                .get("browser.wal_present")
                .unwrap()
                .as_bool(),
            Some(true)
        );
        drop(writer);
    }

    #[test]
    fn missing_schema_and_corruption_report_errors() {
        assert_eq!(
            parse_database(b"not a database", &source("Default"), || Ok(()))
                .unwrap_err()
                .code,
            "CHROMIUM_DATABASE_ERROR"
        );
        let bytes = database("DROP TABLE visits;");
        assert!(parse_database(&bytes, &source("Default"), || Ok(()))
            .unwrap_err()
            .message
            .contains("visits"));
        let bytes = database("INSERT INTO urls VALUES(1,'https://a.example.invalid/','x',-1);");
        assert!(parse_database(&bytes, &source("Default"), || Ok(()))
            .unwrap_err()
            .message
            .contains("negative"));
    }

    #[test]
    fn corrupt_declared_counters_do_not_overflow_or_wrap() {
        let bytes = database(&format!("INSERT INTO urls VALUES(1,'https://a.example.invalid/','same',{}),(2,'https://a.example.invalid/','same',1);", i64::MAX));
        let error = parse_database(&bytes, &source("Default"), || Ok(())).unwrap_err();
        assert!(error.message.contains("overflow"));
    }

    #[test]
    fn failed_profile_makes_totals_explicitly_partial() {
        let mut collection = Collection::default();
        collection
            .add(source("Default"), parse(&fixture()))
            .unwrap();
        collection.failed(source("BrokenProfile"), &db_error("missing visits"));
        let result = collection.finish().unwrap();
        assert!(result
            .summary
            .unwrap()
            .contains("失败 1 个；跨配置统计为部分结果"));
        assert!(result.artifacts.iter().all(|a| a
            .attributes
            .get("browser.partial_profiles")
            .unwrap()
            .as_bool()
            == Some(true)));
        assert!(result.artifacts.iter().any(|a| a
            .attributes
            .get("browser.status")
            .and_then(Value::as_str)
            == Some("failed")));
    }

    #[test]
    fn cancellation_is_not_converted_to_an_empty_profile() {
        assert!(
            parse_database(&fixture(), &source("Default"), || Err(Error::cancelled()))
                .unwrap_err()
                .is_cancelled()
        );
    }

    #[test]
    fn empty_valid_history_is_distinguished_from_a_parse_failure() {
        let stats = parse(&database(""));
        assert_eq!(
            (stats.url_rows, stats.visits, stats.orphan_visits),
            (0, 0, 0)
        );
        let mut collection = Collection::default();
        collection.add(source("Default"), stats).unwrap();
        let result = collection.finish().unwrap();
        assert_eq!(result.artifacts.len(), 1);
        assert_eq!(
            result.artifacts[0]
                .attributes
                .get("browser.status")
                .unwrap()
                .as_str(),
            Some("parsed")
        );
    }

    #[test]
    fn no_profiles_and_all_failed_profiles_do_not_return_successful_zero_totals() {
        assert_eq!(
            Collection::default().finish().unwrap_err().code,
            "NOT_FOUND"
        );
        let mut collection = Collection::default();
        collection.failed(source("Broken"), &db_error("missing visits"));
        let error = collection.finish().unwrap_err();
        assert_eq!(error.code, "CHROMIUM_ALL_PROFILES_FAILED");
        assert!(error.message.contains("Broken/History"));
        assert!(error.message.contains("missing visits"));
    }

    #[test]
    fn profile_output_budget_is_checked_during_sql_row_processing() {
        let bytes = database(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<2600)
             INSERT INTO urls SELECT x, 'https://budget.example.invalid/' || x, 'page ' || x, 1 FROM n;",
        );
        let error = parse_database(&bytes, &source("Default"), || Ok(())).unwrap_err();
        assert_eq!(error.code, "RESOURCE_LIMIT");
        assert!(error.message.contains("profile alone exceeds"));
    }

    #[test]
    fn profile_text_budget_prevents_large_aggregate_copies() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER); CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);").unwrap();
        let text = "x".repeat(8_000);
        for id in 1..140 {
            conn.execute(
                "INSERT INTO urls VALUES(?1,?2,'same',1)",
                rusqlite::params![id, format!("https://text.example.invalid/{id}/{text}")],
            )
            .unwrap();
        }
        let bytes = conn.serialize(DatabaseName::Main).unwrap().to_vec();
        let error = parse_database(&bytes, &source("Default"), || Ok(())).unwrap_err();
        assert_eq!(error.code, "RESOURCE_LIMIT");
        assert!(error.message.contains("text exceeds"));
    }

    #[test]
    fn sqlite_progress_handler_interrupts_cpu_only_sql_for_cancellation() {
        use std::sync::atomic::AtomicUsize;
        let conn = Connection::open_in_memory().unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let guard = SqlGuard::install(
            &conn,
            move || {
                if observed.fetch_add(1, Ordering::SeqCst) >= 2 {
                    Err(Error::cancelled())
                } else {
                    Ok(())
                }
            },
            SQL_BUDGET,
        );
        let error = conn.query_row(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000) SELECT SUM(x) FROM n",
            [], |row| row.get::<_, i64>(0),
        ).unwrap_err();
        assert!(guard.error(error).is_cancelled());
        assert!(calls.load(Ordering::SeqCst) >= 3);
    }

    #[test]
    fn sqlite_progress_handler_enforces_query_time_budget_without_sleeping() {
        let conn = Connection::open_in_memory().unwrap();
        let guard = SqlGuard::install(&conn, || Ok(()), Duration::ZERO);
        let error = conn.query_row(
            "WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<1000000) SELECT SUM(x) FROM n",
            [], |row| row.get::<_, i64>(0),
        ).unwrap_err();
        let error = guard.error(error);
        assert_eq!(error.code, "RESOURCE_LIMIT");
        assert!(error.message.contains("query time budget"));
    }
}
