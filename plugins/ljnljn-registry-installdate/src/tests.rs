use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRun};

use super::testhive::{build_hive, utf16_bytes, KeySpec};
use super::{AUX_VALUES, TARGET_KEY};

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
            "ljnljn-installdate-{label}-{}-{unique}",
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

fn utf16(text: &str) -> Vec<u8> {
    let mut out = utf16_bytes(text);
    out.extend_from_slice(&[0, 0]);
    out
}

fn dword(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn filetime_u64(unix_seconds: u64) -> u64 {
    (unix_seconds + 11_644_473_600) * 10_000_000
}

/// Names the hive in the base block and gives it a header last-write time.
fn finish(mut bytes: Vec<u8>, file_name: &str) -> Vec<u8> {
    bytes[0x0C..0x14].copy_from_slice(&filetime_u64(1_704_067_200).to_le_bytes());
    bytes[0x30..0x70].fill(0);
    let mut name = utf16_bytes(file_name);
    name.truncate(64);
    bytes[0x30..0x30 + name.len()].copy_from_slice(&name);
    bytes
}

fn current_version(values: Vec<(&str, u32, Vec<u8>)>) -> KeySpec {
    let mut key = KeySpec::new("CurrentVersion").last_write(filetime_u64(1_704_153_600));
    for (name, kind, data) in values {
        key = key.value(name, kind, data);
    }
    key
}

fn software_hive(values: Vec<(&str, u32, Vec<u8>)>) -> Vec<u8> {
    finish(
        build_hive(
            &KeySpec::new("SOFTWARE").child(
                KeySpec::new("Microsoft")
                    .child(KeySpec::new("Windows NT").child(current_version(values))),
            ),
        ),
        "SOFTWARE",
    )
}

fn run_system(root: &Path, analyzer: &str, inputs: &[&str]) -> TestRun {
    Harness::new(super::plugin)
        .run_with_inputs(
            analyzer,
            Fixture::system("windows", root),
            inputs,
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .expect("run")
}

fn value_record(run: &TestRun) -> &lovelycarve_plugin::testing::TestRecord {
    &run.of_type("windows.installdate.value")[0]
}

#[test]
fn system_run_parses_dword_install_date_and_aux_values() {
    let fixture = FixtureDir::new("dword");
    fixture.write(
        "Windows/System32/config/SOFTWARE",
        &software_hive(vec![
            ("ProductName", 1, utf16("Windows 11 Pro")),
            ("CurrentVersion", 1, utf16("10.0")),
            ("CurrentBuild", 1, utf16("22631")),
            ("UBR", 4, dword(3155)),
            ("InstallDate", 4, dword(1_620_038_668)),
        ]),
    );
    let run = run_system(
        &fixture.path,
        "installdate",
        &["Windows/System32/config/SOFTWARE"],
    );

    assert_eq!(run.count("windows.installdate.hive"), 1);
    assert_eq!(run.count("windows.installdate.key"), 1);
    assert_eq!(run.count("windows.installdate.value"), 1);
    assert_eq!(run.count("windows.installdate.aux"), 4);
    assert_eq!(run.count("windows.installdate.limitation"), 1);

    let hive = &run.of_type("windows.installdate.hive")[0];
    assert_eq!(hive.text("file_name"), Some("SOFTWARE"));
    assert_eq!(hive.text("version"), Some("1.5"));
    assert_eq!(hive.text("checksum_state"), Some("placeholder_zero"));
    assert_eq!(
        hive.get("regf_valid").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        hive.text("header_last_write"),
        Some("2024-01-01T00:00:00Z")
    );

    let key = &run.of_type("windows.installdate.key")[0];
    assert_eq!(key.text("target"), Some(TARGET_KEY));
    assert_eq!(
        key.get("exists").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(
        key.text("resolved_path"),
        Some(r"Microsoft\Windows NT\CurrentVersion")
    );
    assert_eq!(
        key.text("last_write"),
        Some("2024-01-02T00:00:00Z")
    );
    assert_eq!(key.int("value_count"), Some(5));
    let names = key.get("value_names").and_then(|value| value.as_array());
    assert_eq!(names.map(|names| names.len()), Some(5));

    let value = value_record(&run);
    assert_eq!(value.text("state"), Some("parsed"));
    assert_eq!(value.text("raw_type"), Some("REG_DWORD"));
    assert_eq!(value.int("raw_value"), Some(1_620_038_668));
    assert_eq!(value.text("utc"), Some("2021-05-03T10:44:28Z"));
    assert_eq!(value.text("plausibility"), Some("plausible"));
    assert_eq!(value.text("hex"), Some("0x608fd40c"));
    assert_eq!(value.text("raw_hex"), Some("0c d4 8f 60"));
    assert_eq!(
        value.text("raw_display"),
        Some("1620038668（REG_DWORD 原值，Unix 秒，本地时区未知）")
    );
    assert_eq!(value.sources.len(), 1);
    assert_eq!(
        value.sources[0].path.as_deref(),
        Some("Windows/System32/config/SOFTWARE")
    );

    let aux = run.of_type("windows.installdate.aux");
    let product = aux
        .iter()
        .find(|record| record.text("name") == Some("ProductName"))
        .expect("ProductName");
    assert_eq!(product.text("value"), Some("Windows 11 Pro"));
    assert_eq!(
        aux.iter()
            .find(|record| record.text("name") == Some("UBR"))
            .and_then(|record| record.text("value")),
        Some("3155")
    );
    assert!(run.warnings.is_empty(), "{:?}", run.warnings);
    assert!(run
        .summary
        .as_deref()
        .unwrap_or("")
        .contains("InstallDate 已解析 1"));
}

#[test]
fn decimal_and_hex_string_install_dates_are_parsed() {
    for (text, hex_notation) in [("1620038668", false), ("0x608fd40c", true)] {
        let fixture = FixtureDir::new("string");
        fixture.write(
            "Windows/System32/config/SOFTWARE",
            &software_hive(vec![("InstallDate", 1, utf16(text))]),
        );
        let run = run_system(
            &fixture.path,
            "installdate",
            &["Windows/System32/config/SOFTWARE"],
        );
        let value = value_record(&run);
        assert_eq!(value.text("state"), Some("parsed"), "{text}");
        assert_eq!(value.int("raw_value"), Some(1_620_038_668));
        assert_eq!(value.text("utc"), Some("2021-05-03T10:44:28Z"));
        assert_eq!(
            value
                .get("text_hex_notation")
                .and_then(|value| value.as_bool()),
            Some(hex_notation)
        );
    }
}

#[test]
fn zero_value_is_unusable_without_a_fabricated_time() {
    let fixture = FixtureDir::new("zero");
    fixture.write(
        "Windows/System32/config/SOFTWARE",
        &software_hive(vec![("InstallDate", 4, dword(0))]),
    );
    let run = run_system(
        &fixture.path,
        "installdate",
        &["Windows/System32/config/SOFTWARE"],
    );
    let value = value_record(&run);
    assert_eq!(value.text("state"), Some("unusable"));
    assert_eq!(value.text("plausibility"), Some("zero"));
    assert_eq!(value.text("utc"), None);
    assert_eq!(value.int("raw_value"), Some(0));
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INSTALL_DATE_ZERO"));
}

#[test]
fn unsupported_type_keeps_raw_bytes_only() {
    let fixture = FixtureDir::new("binary");
    fixture.write(
        "Windows/System32/config/SOFTWARE",
        &software_hive(vec![(
            "InstallDate",
            3,
            vec![0x60, 0x8f, 0xd4, 0x0c, 0x00, 0x00],
        )]),
    );
    let run = run_system(
        &fixture.path,
        "installdate",
        &["Windows/System32/config/SOFTWARE"],
    );
    let value = value_record(&run);
    assert_eq!(value.text("state"), Some("unusable"));
    assert_eq!(value.text("raw_type"), Some("REG_BINARY"));
    assert_eq!(value.text("raw_hex"), Some("60 8f d4 0c 00 00"));
    assert_eq!(value.text("utc"), None);
    assert_eq!(value.int("raw_value"), None);
}

#[test]
fn implausible_value_keeps_utc_but_is_marked_unusable() {
    let fixture = FixtureDir::new("implausible");
    fixture.write(
        "Windows/System32/config/SOFTWARE",
        &software_hive(vec![("InstallDate", 4, dword(86_400))]),
    );
    let run = run_system(
        &fixture.path,
        "installdate",
        &["Windows/System32/config/SOFTWARE"],
    );
    let value = value_record(&run);
    assert_eq!(value.text("state"), Some("unusable"));
    assert_eq!(value.text("plausibility"), Some("implausible"));
    assert_eq!(value.text("utc"), Some("1970-01-02T00:00:00Z"));
}

#[test]
fn missing_target_key_is_reported_as_a_typed_absence() {
    let fixture = FixtureDir::new("missing-key");
    fixture.write(
        "Windows/System32/config/SOFTWARE",
        &finish(build_hive(&KeySpec::new("SOFTWARE")), "SOFTWARE"),
    );
    let run = run_system(
        &fixture.path,
        "installdate",
        &["Windows/System32/config/SOFTWARE"],
    );
    let key = &run.of_type("windows.installdate.key")[0];
    assert_eq!(
        key.get("exists").and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(key.text("missing_segment"), Some("Microsoft"));
    let value = value_record(&run);
    assert_eq!(value.text("state"), Some("missing"));
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "TARGET_KEY_MISSING"));
}

#[test]
fn key_without_install_date_is_missing_not_zero() {
    let fixture = FixtureDir::new("missing-value");
    fixture.write(
        "Windows/System32/config/SOFTWARE",
        &software_hive(vec![("ProductName", 1, utf16("Windows 10"))]),
    );
    let run = run_system(
        &fixture.path,
        "installdate",
        &["Windows/System32/config/SOFTWARE"],
    );
    let value = value_record(&run);
    assert_eq!(value.text("state"), Some("missing"));
    assert_eq!(value.int("raw_value"), None);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INSTALL_DATE_MISSING"));
}

#[test]
fn invalid_hive_is_rejected_with_its_own_reason() {
    let fixture = FixtureDir::new("invalid");
    fixture.write("Windows/System32/config/SOFTWARE", b"not a registry hive");
    let run = run_system(
        &fixture.path,
        "installdate",
        &["Windows/System32/config/SOFTWARE"],
    );
    let hive = &run.of_type("windows.installdate.hive")[0];
    assert_eq!(
        hive.get("regf_valid").and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(hive.text("error_code"), Some("HIVE_TOO_SHORT"));
    assert_eq!(run.count("windows.installdate.value"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "HIVE_TOO_SHORT"));
}

#[test]
fn checksum_mismatch_is_reported_but_does_not_hide_the_value() {
    let fixture = FixtureDir::new("checksum");
    let mut bytes = software_hive(vec![("InstallDate", 4, dword(1_620_038_668))]);
    // A non-zero checksum that does not match the computed one.
    bytes[0x1FC..0x200].copy_from_slice(&0xA5A5_5A5Au32.to_le_bytes());
    fixture.write("Windows/System32/config/SOFTWARE", &bytes);
    let run = run_system(
        &fixture.path,
        "installdate",
        &["Windows/System32/config/SOFTWARE"],
    );
    let hive = &run.of_type("windows.installdate.hive")[0];
    assert_eq!(hive.text("checksum_state"), Some("mismatch"));
    assert_eq!(value_record(&run).text("state"), Some("parsed"));
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "HEADER_CHECKSUM_MISMATCH"));
}

#[test]
fn file_analyzer_analyzes_a_selected_hive() {
    let fixture = FixtureDir::new("file");
    let path = fixture.write(
        "exported/SOFTWARE",
        &software_hive(vec![("InstallDate", 4, dword(1_620_038_668))]),
    );
    let run = Harness::new(super::plugin)
        .run("installdate_file", Fixture::files(&[path.as_path()]))
        .expect("run");
    assert_eq!(value_record(&run).text("state"), Some("parsed"));
    let hive = &run.of_type("windows.installdate.hive")[0];
    assert_eq!(
        hive.sources[0].root.as_deref(),
        Some("files"),
        "file runs use the host's synthetic files root"
    );
}

#[test]
fn evidence_analyzer_walks_every_volume() {
    let first = FixtureDir::new("evidence-1");
    first.write(
        "Windows/System32/config/SOFTWARE",
        &software_hive(vec![("InstallDate", 4, dword(1_620_038_668))]),
    );
    let second = FixtureDir::new("evidence-2");
    second.write("Users/alice/NTUSER.DAT", b"placeholder");
    let run = Harness::new(super::plugin)
        .run_with_inputs(
            "installdate_evidence",
            Fixture::evidence(&[("part:1", &first.path), ("part:2", &second.path)]),
            &["*/Windows/System32/config/SOFTWARE"],
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .expect("run");
    assert_eq!(run.count("windows.installdate.value"), 1);
    assert_eq!(value_record(&run).sources[0].root.as_deref(), Some("part:1"));
}

#[test]
fn undeclared_inputs_produce_an_explicit_warning() {
    let fixture = FixtureDir::new("empty");
    let run = run_system(
        &fixture.path,
        "installdate",
        &["Windows/System32/config/SOFTWARE"],
    );
    assert_eq!(run.count("windows.installdate.value"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}

#[test]
fn coverage_limitations_are_preserved_as_a_record() {
    let fixture = FixtureDir::new("limits");
    fixture.write(
        "Windows/System32/config/SOFTWARE",
        &software_hive(vec![("InstallDate", 4, dword(1_620_038_668))]),
    );
    let run = run_system(
        &fixture.path,
        "installdate",
        &["Windows/System32/config/SOFTWARE"],
    );
    let limitation = &run.of_type("windows.installdate.limitation")[0];
    assert_eq!(limitation.text("subject"), Some("coverage"));
    let items = limitation
        .get("items")
        .and_then(|value| value.as_array())
        .expect("items");
    assert_eq!(items.len(), super::LIMITATIONS.len());
    assert_eq!(AUX_VALUES.len(), 12);
}
