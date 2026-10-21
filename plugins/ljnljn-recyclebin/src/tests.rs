use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRun};

use super::parser::tests::fixture;
use super::parser::MAX_RECORD_BYTES;
use super::{component, paired_path};

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
            "ljnljn-recyclebin-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let file = self.path.join(relative);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, bytes).unwrap();
        file
    }

    fn directory(&self, relative: &str) -> PathBuf {
        let directory = self.path.join(relative);
        fs::create_dir_all(&directory).unwrap();
        directory
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn harness() -> Harness {
    Harness::new(super::plugin)
}

fn run_file(path: &Path) -> TestRun {
    harness()
        .run("recyclebin_files", Fixture::files(&[path]))
        .expect("file run")
}

fn run_evidence(volume: &Path) -> TestRun {
    harness()
        .run(
            "recyclebin_evidence",
            Fixture::evidence(&[("part:1", volume)]),
        )
        .expect("evidence run")
}

fn boolean(run: &TestRun, field: &str) -> Option<bool> {
    run.of_type("windows.recyclebin.entry")[0]
        .get(field)
        .and_then(|value| value.as_bool())
}

#[test]
fn file_analyzer_emits_typed_entry_with_utc_timestamp_and_source() {
    let fixture_dir = FixtureDir::new("file");
    let path = fixture_dir.write("$IABC123.txt", &fixture(2, r"C:\Users\example\报告😀.txt"));
    let run = run_file(&path);

    assert_eq!(run.count("windows.recyclebin.entry"), 1);
    let record = run.of_type("windows.recyclebin.entry")[0];
    assert_eq!(record.text("original_name"), Some("报告😀.txt"));
    assert_eq!(
        record.text("original_path"),
        Some(r"C:\Users\example\报告😀.txt")
    );
    assert_eq!(record.int("original_size"), Some(42));
    assert_eq!(record.int("version"), Some(2));
    assert_eq!(
        record.text("deleted_at"),
        Some("1970-01-01T00:00:01.0000001Z"),
        "deletion FILETIME must be a UTC RFC 3339 timestamp"
    );
    assert_eq!(
        record.int("deleted_filetime"),
        Some(116_444_736_010_000_001)
    );
    assert_eq!(
        record.text("companion_state"),
        Some("not_checked_file_scope")
    );
    assert!(record.get("companion_present").is_none());

    assert_eq!(record.sources.len(), 1);
    assert_eq!(record.sources[0].offset, Some(0));
    assert_eq!(
        record.sources[0].length,
        Some(fs::metadata(&path).unwrap().len())
    );
    assert_eq!(record.sources[0].note.as_deref(), Some("$IABC123.txt"));
    assert!(run
        .summary
        .as_deref()
        .unwrap_or("")
        .contains("输出 1 条记录"));
}

#[test]
fn malformed_file_is_a_warning_not_an_empty_success() {
    let fixture_dir = FixtureDir::new("invalid");
    let path = fixture_dir.write("$IBROKEN.txt", b"not recycle-bin metadata");
    let run = run_file(&path);

    assert_eq!(run.count("windows.recyclebin.entry"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, message, file)| code == "INVALID_RECYCLE_METADATA"
            && message.contains("$IBROKEN.txt")
            && file.as_deref() == Some("$IBROKEN.txt")));
    assert!(run
        .summary
        .as_deref()
        .unwrap_or("")
        .contains("损坏/不支持 1"));
}

#[test]
fn oversized_file_is_a_resource_limit_warning() {
    let fixture_dir = FixtureDir::new("oversized");
    let path = fixture_dir.write("$IBIG.txt", &vec![0_u8; MAX_RECORD_BYTES + 1]);
    let run = run_file(&path);

    assert_eq!(run.count("windows.recyclebin.entry"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "RESOURCE_LIMIT"));
}

#[test]
fn empty_file_selection_returns_an_explicit_warning() {
    let run = harness()
        .run("recyclebin_files", Fixture::files(&[]))
        .expect("file run");

    assert_eq!(run.count("windows.recyclebin.entry"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}

#[test]
fn evidence_analyzer_scans_recycle_bin_and_checks_companion() {
    let fixture_dir = FixtureDir::new("evidence");
    fixture_dir.write(
        "volume/$Recycle.Bin/S-1-5-21-example/$IABC123.txt",
        &fixture(2, r"C:\Users\example\report.txt"),
    );
    fixture_dir.write(
        "volume/$Recycle.Bin/S-1-5-21-example/$RABC123.txt",
        &[0x41; 42],
    );
    let volume = fixture_dir.directory("volume");
    let run = run_evidence(&volume);

    assert_eq!(run.count("windows.recyclebin.entry"), 1);
    let record = run.of_type("windows.recyclebin.entry")[0];
    assert_eq!(record.text("original_name"), Some("report.txt"));
    assert_eq!(record.text("companion_state"), Some("present_file"));
    assert_eq!(boolean(&run, "companion_present"), Some(true));
    assert_eq!(record.int("companion_size"), Some(42));
    assert_eq!(boolean(&run, "size_matches"), Some(true));
    assert_eq!(
        record.text("companion_path"),
        Some("part:1/$Recycle.Bin/S-1-5-21-example/$RABC123.txt")
    );

    assert_eq!(record.sources.len(), 1);
    assert_eq!(record.sources[0].root.as_deref(), Some("part:1"));
    assert_eq!(
        record.sources[0].path.as_deref(),
        Some("$Recycle.Bin/S-1-5-21-example/$IABC123.txt")
    );
    assert_eq!(
        record.sources[0].note.as_deref(),
        Some("part:1/$Recycle.Bin/S-1-5-21-example/$IABC123.txt")
    );
}

#[test]
fn evidence_analyzer_reports_missing_companion_and_invalid_metadata() {
    let fixture_dir = FixtureDir::new("mixed");
    fixture_dir.write(
        "volume/$Recycle.Bin/S-1-5-21-example/$IMISSING.txt",
        &fixture(1, r"C:\Users\example\gone.txt"),
    );
    fixture_dir.write(
        "volume/$Recycle.Bin/S-1-5-21-example/$IBROKEN.txt",
        b"broken",
    );
    let volume = fixture_dir.directory("volume");
    let run = run_evidence(&volume);

    assert_eq!(run.count("windows.recyclebin.entry"), 1);
    let record = run.of_type("windows.recyclebin.entry")[0];
    assert_eq!(record.text("original_name"), Some("gone.txt"));
    assert_eq!(record.text("companion_state"), Some("missing"));
    assert_eq!(boolean(&run, "companion_present"), Some(false));
    assert!(record.get("companion_size").is_none());

    assert!(run.warnings.iter().any(|(code, message, _)| {
        code == "INVALID_RECYCLE_METADATA" && message.contains("$IBROKEN.txt")
    }));
    assert!(run
        .summary
        .as_deref()
        .unwrap_or("")
        .contains("损坏/不支持 1"));
}

#[test]
fn evidence_analyzer_reports_volumes_without_recycle_bin() {
    let fixture_dir = FixtureDir::new("norecycle");
    fixture_dir.directory("volume/Users/example");
    let volume = fixture_dir.directory("volume");
    let run = run_evidence(&volume);

    assert_eq!(run.count("windows.recyclebin.entry"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "RECYCLE_BIN_NOT_FOUND"));
}

#[test]
fn companion_path_never_resolves_the_original_windows_path() {
    assert_eq!(
        paired_path("$Recycle.Bin/S-1-5-21-example/$IABC123.txt").unwrap(),
        "$Recycle.Bin/S-1-5-21-example/$RABC123.txt"
    );
    assert!(paired_path("plain.txt").is_none());
    assert!(!component("../escape"));
    assert!(!component("x\\y"));
    assert!(!component("x/y"));
}
