//! Read-only, main-database-only SQLite access for Chromium `History`.
//!
//! The host hands the analyzer a logical file handle; SQLite needs a path,
//! so the bytes are copied to a private create-new temporary file and opened
//! with `mode=ro&immutable=1`. The evidence is never modified, and the
//! `-wal` / `-shm` sidecars are neither read nor merged: the visited rows
//! that still live in the WAL are not in this snapshot and every record says
//! so.
//!
//! The query layer keeps the v1 plugin's limits: 64 MiB per database,
//! 100,000 URL rows, 5,000,000 visits, 100,000 downloads, a 1 MiB text
//! budget per profile and a 30-second SQL budget with cancellation polling
//! through SQLite's progress handler.

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

use lovelycarve_plugin::{Context, Error, Result};
use rusqlite::{types::ValueRef, Connection, OpenFlags, Row};

pub const MAX_DB_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_URL_ROWS: i64 = 100_000;
pub const MAX_VISITS: i64 = 5_000_000;
pub const MAX_DOWNLOADS: i64 = 100_000;
pub const MAX_PROFILE_TEXT_BYTES: usize = 1024 * 1024;
pub const SQL_BUDGET: Duration = Duration::from_secs(30);
pub const MAIN_ONLY_NOTE: &str = "仅统计主 History 数据库；WAL/SHM 未合并，可能遗漏尚在 WAL 中的访问。标题取 urls.title 当前值，不代表每次访问时的标题。";

/// Chromium's epoch: 1601-01-01T00:00:00Z in microseconds.
pub const CHROMIUM_EPOCH_MICROS: i64 = 11_644_473_600_000_000;
/// Largest Unix second ISO 8601 can express (`9999-12-31T23:59:59Z`).
pub const MAX_UNIX_SECONDS: i64 = 253_402_300_799;

/// One History database and the profile it belongs to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Source {
    pub root: String,
    pub path: String,
    pub browser: String,
    pub profile: String,
    pub wal: Option<bool>,
    pub shm: Option<bool>,
}

impl Source {
    pub fn key(&self) -> String {
        format!("{}:{}", self.browser, self.profile)
    }
}

#[derive(Clone, Debug, Default)]
pub struct Aggregate {
    pub visits: i64,
    pub declared: i64,
    pub url_rows: i64,
    pub first: Option<i64>,
    pub last: Option<i64>,
    pub titles: BTreeSet<String>,
    pub urls: BTreeSet<String>,
    pub profiles: BTreeSet<String>,
    pub browsers: BTreeSet<String>,
}

impl Aggregate {
    pub fn merge(&mut self, other: &Self, profile: &str, browser: &str) -> Result<()> {
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
            (Some(left), Some(right)) => Some(left.min(right)),
            (left, right) => left.or(right),
        };
        self.last = match (self.last, other.last) {
            (Some(left), Some(right)) => Some(left.max(right)),
            (left, right) => left.or(right),
        };
        self.titles.extend(other.titles.iter().cloned());
        self.urls.extend(other.urls.iter().cloned());
        self.profiles.insert(profile.to_owned());
        self.browsers.insert(browser.to_owned());
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
pub struct DownloadRow {
    pub id: Option<i64>,
    pub target_path: Option<String>,
    pub tab_url: Option<String>,
    pub referrer: Option<String>,
    pub site_url: Option<String>,
    pub start_time: Option<i64>,
    pub received_bytes: Option<i64>,
    pub total_bytes: Option<i64>,
    pub state: Option<i64>,
    pub danger_type: Option<i64>,
    pub interrupt_reason: Option<i64>,
    pub mime_type: Option<String>,
    pub original_mime_type: Option<String>,
    pub current_path: Option<String>,
}

#[derive(Debug, Default)]
pub struct ProfileStats {
    pub urls: BTreeMap<String, Aggregate>,
    pub titles: BTreeMap<String, Aggregate>,
    pub url_rows: i64,
    pub visits: i64,
    pub orphan_visits: i64,
    pub wal_header: bool,
    pub downloads: Vec<DownloadRow>,
}

/// Columns read from `downloads`; only those the database actually has are
/// selected, and the SQL string is built from this fixed list.
const DOWNLOAD_COLUMNS: [&str; 14] = [
    "id",
    "target_path",
    "tab_url",
    "referrer",
    "site_url",
    "start_time",
    "received_bytes",
    "total_bytes",
    "state",
    "danger_type",
    "interrupt_reason",
    "mime_type",
    "original_mime_type",
    "current_path",
];

pub fn db_error(error: impl std::fmt::Display) -> Error {
    Error::new("CHROMIUM_DATABASE_ERROR", error.to_string())
}

pub fn limit(message: impl Into<String>) -> Error {
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

/// Polls cancellation from inside SQLite, including COUNT and the first
/// JOIN step, and enforces the query time budget.
struct SqlGuard {
    context: Context,
    started: Instant,
    budget: Duration,
    interrupted: Arc<Mutex<Option<Error>>>,
}

impl SqlGuard {
    fn install(conn: &Connection, context: Context, budget: Duration) -> Self {
        let guard = Self {
            context,
            started: Instant::now(),
            budget,
            interrupted: Arc::new(Mutex::new(None)),
        };
        let check = guard.context.clone();
        let interrupted = guard.interrupted.clone();
        let started = guard.started;
        conn.progress_handler(
            10_000,
            Some(move || {
                let error = check.check_cancelled().err().or_else(|| {
                    (started.elapsed() >= budget).then(|| {
                        limit("SQLite exceeded its query time budget (30 seconds)")
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
        self.context.check_cancelled()?;
        if self.started.elapsed() >= self.budget {
            return Err(limit("SQLite exceeded its query time budget (30 seconds)"));
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

pub fn parse_database(bytes: &[u8], source: &Source, context: &Context) -> Result<ProfileStats> {
    context.check_cancelled()?;
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
    let guard = SqlGuard::install(&conn, context.clone(), SQL_BUDGET);
    let sql_error = |error| guard.error(error);
    conn.execute_batch(
        "PRAGMA query_only=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=MEMORY;",
    )
    .map_err(sql_error)?;
    for table in ["urls", "visits"] {
        if !table_exists(&conn, table).map_err(sql_error)? {
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
    if !unique_integer_ids(&conn, "urls", url_rows).map_err(sql_error)? {
        return Err(db_error("urls.id must contain unique integer identifiers"));
    }
    if !unique_integer_ids(&conn, "visits", visits).map_err(sql_error)? {
        return Err(db_error("visits.id must contain unique integer identifiers"));
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
    let mut processed = 0_u64;
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
            ..Aggregate::default()
        };
        stats
            .urls
            .entry(url)
            .or_default()
            .merge(&aggregate, &source.profile, &source.browser)?;
        stats
            .titles
            .entry(title)
            .or_default()
            .merge(&aggregate, &source.profile, &source.browser)?;
        if 1 + 2 * (stats.urls.len() + stats.titles.len()) > 10_000 {
            return Err(limit("History profile alone exceeds 10000 metric items"));
        }
    }
    stats.orphan_visits = visits - joined_visits;
    if stats.orphan_visits < 0 {
        return Err(db_error("invalid visits / urls join cardinality"));
    }
    guard.check()?;
    stats.downloads = read_downloads(&conn, &guard)?;
    guard.check()?;
    Ok(stats)
}

fn table_exists(conn: &Connection, name: &str) -> std::result::Result<bool, rusqlite::Error> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name=?1",
        [name],
        |row| row.get(0),
    )?;
    Ok(count == 1)
}

fn unique_integer_ids(
    conn: &Connection,
    table: &str,
    expected: i64,
) -> std::result::Result<bool, rusqlite::Error> {
    let sql = format!("SELECT COUNT(DISTINCT id) FROM {table} WHERE typeof(id)='integer'");
    let ids: i64 = conn.query_row(&sql, [], |row| row.get(0))?;
    Ok(ids == expected)
}

fn read_downloads(conn: &Connection, guard: &SqlGuard) -> Result<Vec<DownloadRow>> {
    if !table_exists(conn, "downloads").map_err(|error| guard.error(error))? {
        return Ok(Vec::new());
    }
    let mut statement = conn
        .prepare("PRAGMA table_info(downloads)")
        .map_err(|error| guard.error(error))?;
    let present: BTreeSet<String> = statement
        .query_map([], |row| row.get::<_, String>(1))
        .map_err(|error| guard.error(error))?
        .filter_map(|name| name.ok())
        .map(|name| name.to_ascii_lowercase())
        .collect();
    drop(statement);
    if present.is_empty() {
        return Ok(Vec::new());
    }
    let mut select = String::new();
    for (index, column) in DOWNLOAD_COLUMNS.iter().enumerate() {
        if index > 0 {
            select.push(',');
        }
        if present.contains(*column) {
            select.push_str(&format!("\"{column}\""));
        } else {
            select.push_str("NULL");
        }
    }
    let sql = format!("SELECT {select} FROM downloads LIMIT {}", MAX_DOWNLOADS + 1);
    let mut statement = conn.prepare(&sql).map_err(|error| guard.error(error))?;
    let mut rows = statement.query([]).map_err(|error| guard.error(error))?;
    let mut downloads = Vec::new();
    while let Some(row) = rows.next().map_err(|error| guard.error(error))? {
        if downloads.len() % 128 == 0 {
            guard.check()?;
        }
        if downloads.len() as i64 >= MAX_DOWNLOADS {
            return Err(limit("History exceeds 100000 download rows"));
        }
        downloads.push(download_row(row));
    }
    Ok(downloads)
}

fn download_row(row: &Row<'_>) -> DownloadRow {
    DownloadRow {
        id: int_at(row, 0),
        target_path: text_at(row, 1),
        tab_url: text_at(row, 2),
        referrer: text_at(row, 3),
        site_url: text_at(row, 4),
        start_time: int_at(row, 5),
        received_bytes: int_at(row, 6),
        total_bytes: int_at(row, 7),
        state: int_at(row, 8),
        danger_type: int_at(row, 9),
        interrupt_reason: int_at(row, 10),
        mime_type: text_at(row, 11),
        original_mime_type: text_at(row, 12),
        current_path: text_at(row, 13),
    }
}

fn int_at(row: &Row<'_>, index: usize) -> Option<i64> {
    match row.get_ref(index).ok()? {
        ValueRef::Integer(value) => Some(value),
        _ => None,
    }
}

fn text_at(row: &Row<'_>, index: usize) -> Option<String> {
    match row.get_ref(index).ok()? {
        ValueRef::Text(bytes) => Some(String::from_utf8_lossy(bytes).into_owned()),
        _ => None,
    }
}

/// Chromium microseconds (1601 epoch) as UTC, or `None` for unset and
/// out-of-range values. Chromium stores UTC, so a UTC timestamp is truthful.
pub fn chromium_time(micros: i64) -> Option<lovelycarve_plugin::Timestamp> {
    if micros <= 0 {
        return None;
    }
    let unix_micros = i128::from(micros) - i128::from(CHROMIUM_EPOCH_MICROS);
    let max = i128::from(MAX_UNIX_SECONDS) * 1_000_000 + 999_999;
    if unix_micros > max {
        return None;
    }
    let seconds = i64::try_from(unix_micros.div_euclid(1_000_000)).ok()?;
    let nanos = (unix_micros.rem_euclid(1_000_000) as u32) * 1_000;
    Some(lovelycarve_plugin::Timestamp::from_unix_nanos(
        seconds, nanos,
    ))
}
