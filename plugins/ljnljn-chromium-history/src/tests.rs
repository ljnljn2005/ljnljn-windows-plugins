use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRecord, TestRun};
use rusqlite::{Connection, DatabaseName};

use super::query::{chromium_time, CHROMIUM_EPOCH_MICROS, MAX_UNIX_SECONDS};

const EPOCH: i64 = CHROMIUM_EPOCH_MICROS;
const CHROME_GLOB: &str = "Users/*/AppData/Local/Google/Chrome/User Data/*/History";
const EDGE_GLOB: &str = "Users/*/AppData/Local/Microsoft/Edge/User Data/*/History";

struct FixtureDir {
    path: PathBuf,
}

impl FixtureDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ljnljn-chromium-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let path = self.path.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, bytes).unwrap();
        path
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn database_with(sql: &str, downloads: bool) -> Vec<u8> {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT NOT NULL, title TEXT, visit_count INTEGER);
         CREATE TABLE visits(id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
         CREATE INDEX visits_url ON visits(url);",
    )
    .unwrap();
    if downloads {
        conn.execute_batch(
            "CREATE TABLE downloads(
                id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT, referrer TEXT,
                site_url TEXT, start_time INTEGER, received_bytes INTEGER, total_bytes INTEGER,
                state INTEGER, danger_type INTEGER, interrupt_reason INTEGER,
                mime_type TEXT, original_mime_type TEXT, current_path TEXT);",
        )
        .unwrap();
    }
    conn.execute_batch(sql).unwrap();
    conn.serialize(DatabaseName::Main).unwrap().to_vec()
}

fn database(sql: &str) -> Vec<u8> {
    database_with(sql, false)
}

fn fixture_bytes() -> Vec<u8> {
    database_with(
        &format!(
            "INSERT INTO urls VALUES(1,'https://a.example.invalid/','Portal',99);
             INSERT INTO urls VALUES(2,'https://b.example.invalid/','Portal',7);
             INSERT INTO urls VALUES(3,'https://a.example.invalid/','Other',5);
             INSERT INTO urls VALUES(4,'https://unused.example.invalid/',NULL,12);
             INSERT INTO visits VALUES(1,1,{}),(2,1,{}),(3,2,{}),(4,3,{}),(5,999,{});
             INSERT INTO downloads VALUES(
                1,'C:/Temp/report.bin','https://a.example.invalid/','https://ref.example.invalid/',
                'https://a.example.invalid/',{},1024,2048,1,0,0,'application/octet-stream',
                'application/octet-stream','C:/Temp/report.bin');",
            EPOCH + 1_234_567,
            EPOCH + 2_000_000,
            EPOCH + 3_000_000,
            EPOCH + 4_000_000,
            EPOCH + 5_000_000,
            EPOCH + 1_000_000,
        ),
        true,
    )
}

fn run_system(root: &Path) -> TestRun {
    Harness::new(super::plugin)
        .run_with_inputs(
            "history",
            Fixture::system("windows", root),
            &[CHROME_GLOB, EDGE_GLOB],
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .expect("run")
}

fn record<'a>(run: &'a TestRun, record_type: &str, field: &str, value: &str) -> &'a TestRecord {
    run.of_type(record_type)
        .into_iter()
        .find(|record| record.text(field) == Some(value))
        .unwrap_or_else(|| panic!("missing {record_type} with {field}={value:?}"))
}

#[test]
fn file_run_emits_url_title_and_download_records() {
    let fixture = FixtureDir::new("file");
    let path = fixture.write("exported/History", &fixture_bytes());
    let run = Harness::new(super::plugin)
        .run("history_file", Fixture::files(&[path.as_path()]))
        .expect("run");

    let profile = &run.of_type("browser.profile")[0];
    assert_eq!(profile.text("browser"), Some("Chromium"));
    assert_eq!(profile.text("profile"), Some("History"));
    assert_eq!(profile.text("status"), Some("parsed"));
    assert_eq!(profile.int("url_rows"), Some(4));
    assert_eq!(profile.int("visits"), Some(5));
    assert_eq!(profile.int("orphan_visits"), Some(1));
    assert_eq!(profile.int("downloads"), Some(1));
    assert_eq!(profile.text("snapshot_scope"), Some("main_database_only"));
    assert_eq!(profile.get("wal_present"), None);
    assert!(profile
        .text("snapshot_note")
        .unwrap_or("")
        .contains("WAL/SHM 未合并"));

    let a = record(&run, "browser.url.profile", "url", "https://a.example.invalid/");
    assert_eq!(a.int("visits"), Some(3));
    assert_eq!(a.int("declared_visits"), Some(104));
    assert_eq!(a.int("url_rows"), Some(2));
    assert_eq!(
        a.get("titles").and_then(|value| value.as_array()).map(|v| v.len()),
        Some(2)
    );
    assert_eq!(a.text("first_visit"), Some("1970-01-01T00:00:01.234567Z"));
    assert_eq!(a.text("last_visit"), Some("1970-01-01T00:00:04Z"));

    let unused = record(
        &run,
        "browser.url.profile",
        "url",
        "https://unused.example.invalid/",
    );
    assert_eq!(unused.int("visits"), Some(0));
    assert_eq!(unused.text("first_visit"), None);

    let portal = record(&run, "browser.title.profile", "title", "Portal");
    assert_eq!(portal.int("visits"), Some(3));
    assert_eq!(portal.int("declared_visits"), Some(106));

    let total = record(&run, "browser.url.total", "url", "https://a.example.invalid/");
    assert_eq!(total.int("visits"), Some(3));
    assert_eq!(total.int("profiles"), Some(1));
    assert_eq!(total.sources.len(), 1);

    let download = &run.of_type("browser.download")[0];
    assert_eq!(download.text("target_path"), Some("C:/Temp/report.bin"));
    assert_eq!(download.text("start_time"), Some("1970-01-01T00:00:01Z"));
    assert_eq!(download.int("received_bytes"), Some(1024));
    assert_eq!(download.int("total_bytes"), Some(2048));
    assert_eq!(download.text("state_name"), Some("complete"));
    assert_eq!(download.text("danger_name"), Some("not_dangerous"));
    assert_eq!(download.sources.len(), 1);

    assert!(run.warnings.is_empty(), "{:?}", run.warnings);
    assert!(run
        .summary
        .as_deref()
        .unwrap_or("")
        .contains("WAL/SHM 未合并"));
}

#[test]
fn system_run_groups_chrome_and_edge_profiles_and_keeps_totals() {
    let fixture = FixtureDir::new("system");
    fixture.write(
        "Users/alice/AppData/Local/Google/Chrome/User Data/Default/History",
        &fixture_bytes(),
    );
    let edge = database_with(
        &format!(
            "INSERT INTO urls VALUES(1,'https://a.example.invalid/','Portal',4),
                (2,'https://c.example.invalid/','Portal',20);
             INSERT INTO visits VALUES(1,1,{}),(2,2,{});",
            EPOCH + 6_000_000,
            EPOCH + 7_000_000,
        ),
        false,
    );
    fixture.write(
        "Users/alice/AppData/Local/Microsoft/Edge/User Data/WorkProfile/History",
        &edge,
    );
    let run = run_system(&fixture.path);

    assert_eq!(run.count("browser.profile"), 2);
    let chrome = record(&run, "browser.profile", "profile", "alice/Default");
    assert_eq!(chrome.text("browser"), Some("Chrome"));
    let edge_profile = record(&run, "browser.profile", "profile", "alice/WorkProfile");
    assert_eq!(edge_profile.text("browser"), Some("Edge"));
    assert_eq!(
        edge_profile.get("wal_present").and_then(|value| value.as_bool()),
        Some(false)
    );

    let total = record(&run, "browser.url.total", "url", "https://a.example.invalid/");
    assert_eq!(total.int("visits"), Some(4));
    assert_eq!(total.int("declared_visits"), Some(108));
    assert_eq!(total.int("profiles"), Some(2));
    assert_eq!(total.sources.len(), 2);
    let browsers = total.get("browsers").and_then(|value| value.as_array()).unwrap();
    assert_eq!(browsers.len(), 2);

    let portal = record(&run, "browser.title.total", "title", "Portal");
    assert_eq!(portal.int("visits"), Some(5));
    assert_eq!(portal.int("profiles"), Some(2));
    assert_eq!(portal.sources.len(), 2);
}

#[test]
fn wal_and_shm_sidecars_are_reported_but_not_merged() {
    let fixture = FixtureDir::new("wal");
    let history = "Users/bob/AppData/Local/Google/Chrome/User Data/Default/History";
    fixture.write(history, &fixture_bytes());
    fixture.write(
        "Users/bob/AppData/Local/Google/Chrome/User Data/Default/History-wal",
        b"",
    );
    fixture.write(
        "Users/bob/AppData/Local/Google/Chrome/User Data/Default/History-shm",
        b"",
    );
    let run = run_system(&fixture.path);
    let profile = record(&run, "browser.profile", "profile", "bob/Default");
    assert_eq!(
        profile.get("wal_present").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        profile.get("shm_present").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        profile.get("wal_header").and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(profile.text("snapshot_scope"), Some("main_database_only"));
    assert_eq!(profile.int("visits"), Some(5));
}

#[test]
fn corrupt_database_is_a_failed_profile_not_an_empty_success() {
    let fixture = FixtureDir::new("corrupt");
    fixture.write(
        "Users/carol/AppData/Local/Google/Chrome/User Data/Default/History",
        b"not a sqlite database",
    );
    let run = run_system(&fixture.path);
    let profile = &run.of_type("browser.profile")[0];
    assert_eq!(profile.text("status"), Some("failed"));
    assert_eq!(profile.text("error_code"), Some("CHROMIUM_DATABASE_ERROR"));
    assert_eq!(run.count("browser.url.profile"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "CHROMIUM_PROFILE_FAILED"));
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "CHROMIUM_ALL_PROFILES_FAILED"));
}

#[test]
fn missing_downloads_table_is_tolerated() {
    let fixture = FixtureDir::new("no-downloads");
    let path = fixture.write(
        "exported/History",
        &database(&format!(
            "INSERT INTO urls VALUES(1,'https://a.example.invalid/','Portal',1);
             INSERT INTO visits VALUES(1,1,{});",
            EPOCH
        )),
    );
    let run = Harness::new(super::plugin)
        .run("history_file", Fixture::files(&[path.as_path()]))
        .expect("run");
    assert_eq!(run.count("browser.download"), 0);
    assert_eq!(run.count("browser.profile"), 1);
    assert_eq!(run.of_type("browser.profile")[0].text("status"), Some("parsed"));
}

#[test]
fn empty_history_is_parsed_not_reported_as_failure() {
    let fixture = FixtureDir::new("empty-db");
    let path = fixture.write("exported/History", &database(""));
    let run = Harness::new(super::plugin)
        .run("history_file", Fixture::files(&[path.as_path()]))
        .expect("run");
    assert_eq!(run.count("browser.profile"), 1);
    assert_eq!(run.of_type("browser.profile")[0].text("status"), Some("parsed"));
    assert_eq!(run.count("browser.url.profile"), 0);
}

#[test]
fn evidence_run_keeps_volume_sources() {
    let first = FixtureDir::new("evidence-1");
    first.write(
        "Users/dave/AppData/Local/Google/Chrome/User Data/Default/History",
        &fixture_bytes(),
    );
    let second = FixtureDir::new("evidence-2");
    second.write("Users/dave/NTUSER.DAT", b"placeholder");
    let run = Harness::new(super::plugin)
        .run_with_inputs(
            "history_evidence",
            Fixture::evidence(&[("part:1", &first.path), ("part:2", &second.path)]),
            &[&format!("*/{CHROME_GLOB}"), &format!("*/{EDGE_GLOB}")],
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .expect("run");
    assert_eq!(run.count("browser.profile"), 1);
    let profile = &run.of_type("browser.profile")[0];
    assert_eq!(profile.sources[0].root.as_deref(), Some("part:1"));
    assert_eq!(profile.sources[0].path.as_deref(), Some(
        "Users/dave/AppData/Local/Google/Chrome/User Data/Default/History"
    ));
}

#[test]
fn missing_required_table_fails_the_profile_with_the_table_name() {
    let conn = Connection::open_in_memory().unwrap();
    conn.execute_batch(
        "CREATE TABLE urls(id INTEGER PRIMARY KEY, url TEXT, title TEXT, visit_count INTEGER);",
    )
    .unwrap();
    let bytes = conn.serialize(DatabaseName::Main).unwrap().to_vec();
    let fixture = FixtureDir::new("missing-table");
    let path = fixture.write("exported/History", &bytes);
    let run = Harness::new(super::plugin)
        .run("history_file", Fixture::files(&[path.as_path()]))
        .expect("run");
    let profile = &run.of_type("browser.profile")[0];
    assert_eq!(profile.text("status"), Some("failed"));
    assert!(profile.text("error").unwrap_or("").contains("visits"));
}

#[test]
fn negative_declared_visit_count_fails_instead_of_wrapping() {
    let fixture = FixtureDir::new("negative");
    let path = fixture.write(
        "exported/History",
        &database(
            "INSERT INTO urls VALUES(1,'https://a.example.invalid/','x',-1);",
        ),
    );
    let run = Harness::new(super::plugin)
        .run("history_file", Fixture::files(&[path.as_path()]))
        .expect("run");
    let profile = &run.of_type("browser.profile")[0];
    assert_eq!(profile.text("status"), Some("failed"));
    assert!(profile.text("error").unwrap_or("").contains("negative"));
}

#[test]
fn missing_inputs_produce_an_explicit_warning() {
    let fixture = FixtureDir::new("no-inputs");
    let run = run_system(&fixture.path);
    assert_eq!(run.count("browser.profile"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}

#[test]
fn chromium_microseconds_render_utc_and_out_of_range_is_none() {
    assert_eq!(
        chromium_time(EPOCH).map(|value| value.as_str().to_owned()),
        Some("1970-01-01T00:00:00Z".to_owned())
    );
    assert_eq!(
        chromium_time(EPOCH + 1_234_567).map(|value| value.as_str().to_owned()),
        Some("1970-01-01T00:00:01.234567Z".to_owned())
    );
    assert_eq!(
        chromium_time(1).map(|value| value.as_str().to_owned()),
        Some("1601-01-01T00:00:00.000001Z".to_owned())
    );
    assert!(chromium_time(0).is_none());
    assert!(chromium_time(-1).is_none());
    assert!(chromium_time(i64::MAX).is_none());
    assert!(chromium_time((MAX_UNIX_SECONDS + 11_644_473_600 + 1) * 1_000_000).is_none());
}
