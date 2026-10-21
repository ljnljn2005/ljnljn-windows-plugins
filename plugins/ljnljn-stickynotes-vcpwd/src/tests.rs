use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRun};

const CSV: &str = "索引,内容,时间\r\n1,VCpwd: alpha,2024-01-01\r\n2,VCpwd: beta,2024-01-02\r\n3,VCpwd: alpha,2024-01-03\r\n";

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
            "ljnljn-stickynotes-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let file = self.path.join(name);
        fs::write(&file, bytes).unwrap();
        file
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn utf16le(text: &str) -> Vec<u8> {
    let mut bytes = vec![0xFF, 0xFE];
    for unit in text.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    bytes
}

fn harness() -> Harness {
    Harness::new(super::plugin)
}

fn run_file(path: &Path) -> TestRun {
    harness()
        .run("stickynotes_vcpwd", Fixture::files(&[path]))
        .expect("file run")
}

#[test]
fn emits_typed_summary_and_deduplicated_credentials_with_sources() {
    let fixture = FixtureDir::new("happy");
    let path = fixture.write("data.csv", CSV.as_bytes());
    let run = run_file(&path);

    assert_eq!(run.count("stickynotes.file"), 1);
    let summary = run.of_type("stickynotes.file")[0];
    assert_eq!(summary.text("source_file"), Some("data.csv"));
    assert_eq!(summary.text("encoding"), Some("UTF-8"));
    assert_eq!(summary.text("delimiter"), Some("comma"));
    assert_eq!(summary.int("record_count"), Some(4));
    assert_eq!(summary.int("credential_count"), Some(2));
    assert_eq!(summary.int("unparsed_row_count"), Some(0));
    assert_eq!(
        summary.get("has_header").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(summary.int("source_size"), Some(CSV.len() as i64));
    assert_eq!(summary.sources.len(), 1);
    assert_eq!(summary.sources[0].note.as_deref(), Some("data.csv"));
    assert_eq!(summary.sources[0].offset, Some(0));

    assert_eq!(run.count("stickynotes.credential"), 2);
    let credentials = run.of_type("stickynotes.credential");
    assert_eq!(credentials[0].text("value"), Some("alpha"));
    assert_eq!(credentials[0].int("row_index"), Some(2));
    assert_eq!(credentials[0].text("column"), Some("内容"));
    assert_eq!(credentials[0].int("occurrences"), Some(2));
    assert_eq!(credentials[0].text("raw_cell"), Some("VCpwd: alpha"));
    assert_eq!(
        credentials[0]
            .get("truncated")
            .and_then(|value| value.as_bool()),
        Some(false)
    );
    let rows = credentials[0]
        .get("occurrence_rows")
        .expect("occurrence rows")
        .as_array()
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].as_str(), Some("4"));
    assert_eq!(
        credentials[0].sources[0].note.as_deref(),
        Some("row 2, column 内容")
    );
    assert_eq!(credentials[1].text("value"), Some("beta"));
    assert_eq!(credentials[1].int("row_index"), Some(3));
}

#[test]
fn utf16le_export_is_decoded_and_located() {
    let fixture = FixtureDir::new("utf16");
    let path = fixture.write("data.csv", &utf16le("索引,内容\r\n1,VCpwd：金眼睛\r\n"));
    let run = run_file(&path);

    let summary = run.of_type("stickynotes.file")[0];
    assert_eq!(summary.text("encoding"), Some("UTF-16LE"));
    let credential = run.of_type("stickynotes.credential")[0];
    assert_eq!(credential.text("value"), Some("金眼睛"));
    assert_eq!(credential.int("row_index"), Some(2));
}

#[test]
fn no_hit_file_emits_a_summary_with_zero_credentials() {
    let fixture = FixtureDir::new("nohit");
    let path = fixture.write("data.csv", "序号,内容\r\n1,买菜\r\n2,开会\r\n".as_bytes());
    let run = run_file(&path);

    assert_eq!(run.count("stickynotes.file"), 1);
    assert_eq!(run.count("stickynotes.credential"), 0);
    let summary = run.of_type("stickynotes.file")[0];
    assert_eq!(summary.int("credential_count"), Some(0));
    assert_eq!(summary.int("record_count"), Some(3));
    assert!(run.warnings.is_empty());
}

#[test]
fn empty_file_is_reported_with_limitations_not_as_silence() {
    let fixture = FixtureDir::new("empty");
    let path = fixture.write("data.csv", b"");
    let run = run_file(&path);

    assert_eq!(run.count("stickynotes.file"), 1);
    assert_eq!(run.count("stickynotes.credential"), 0);
    let limitations = run.of_type("stickynotes.file")[0]
        .get("limitations")
        .expect("limitations")
        .as_array()
        .unwrap();
    assert!(limitations
        .iter()
        .any(|item| item.as_str().is_some_and(|text| text.contains("文件为空"))));
    assert!(limitations.iter().any(|item| item
        .as_str()
        .is_some_and(|text| text.contains("未覆盖：不实现 VeraCrypt"))));
}

#[test]
fn inconsistent_rows_are_counted_and_warned() {
    let fixture = FixtureDir::new("ragged");
    let path = fixture.write("data.csv", b"a,b\r\n1,VCpwd: x\r\nonly-one\r\n");
    let run = run_file(&path);

    assert_eq!(run.count("stickynotes.file"), 1);
    let summary = run.of_type("stickynotes.file")[0];
    assert_eq!(summary.int("unparsed_row_count"), Some(1));
    assert_eq!(summary.int("credential_count"), Some(1));
    assert!(run
        .warnings
        .iter()
        .any(|(code, message, _)| code == "UNPARSED_ROWS" && message.contains("1 行未解析")));
}

#[test]
fn oversized_credential_value_is_skipped_with_a_warning() {
    let fixture = FixtureDir::new("hugevalue");
    let csv = format!("内容\r\nVCpwd: {}\r\n", "x".repeat(300 * 1024));
    let path = fixture.write("data.csv", csv.as_bytes());
    let run = run_file(&path);

    assert_eq!(run.count("stickynotes.file"), 1);
    assert_eq!(run.count("stickynotes.credential"), 0);
    let summary = run.of_type("stickynotes.file")[0];
    assert_eq!(summary.int("credential_count"), Some(1));
    let limitations = summary
        .get("limitations")
        .expect("limitations")
        .as_array()
        .unwrap();
    assert!(limitations
        .iter()
        .any(|item| item.as_str().is_some_and(|text| text.contains("256 KiB"))));
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "VALUE_TOO_LARGE"));
}

#[test]
fn empty_file_selection_returns_an_explicit_warning() {
    let run = harness()
        .run("stickynotes_vcpwd", Fixture::files(&[]))
        .expect("file run");

    assert_eq!(run.count("stickynotes.file"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}
