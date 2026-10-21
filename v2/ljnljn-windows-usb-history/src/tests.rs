use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness};

use super::testhive::{build_hive, utf16_bytes, KeySpec};

const DEVICE: &str = "Disk&Ven_Ljnljn&Prod_UsbTest&Rev_1.00";
const INSTANCE: &str = "0123456789ABCDEF";

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
            "ljnljn-usb-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn system_hive(&self, bytes: &[u8]) -> PathBuf {
        let directory = self.path.join("Windows/System32/config");
        fs::create_dir_all(&directory).unwrap();
        let hive = directory.join("SYSTEM");
        fs::write(&hive, bytes).unwrap();
        hive
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn filetime_u64(unix_seconds: u64) -> u64 {
    (unix_seconds + 11_644_473_600) * 10_000_000
}

fn filetime(unix_seconds: u64) -> Vec<u8> {
    filetime_u64(unix_seconds).to_le_bytes().to_vec()
}

fn properties(first_install: u64, last_arrival: u64) -> KeySpec {
    KeySpec::new("Properties").child(
        KeySpec::new("83da6326-97a6-4088-9453-a1923f573b29")
            .child(KeySpec::new("0064").value("", 3, filetime(first_install)))
            .child(KeySpec::new("0066").value("", 3, filetime(last_arrival))),
    )
}

fn system_hive() -> Vec<u8> {
    let root = KeySpec::new("ROOT").child(
        KeySpec::new("ControlSet001").child(
            KeySpec::new("Enum").child(
                KeySpec::new("USBSTOR").child(
                    KeySpec::new(DEVICE)
                        .last_write(filetime_u64(1_704_067_200))
                        .value("FriendlyName", 1, utf16_bytes("Ljnljn USB Test"))
                        .value("DeviceDesc", 1, utf16_bytes("USB Mass Storage Device"))
                        .value("Service", 1, utf16_bytes("USBSTOR"))
                        .value("ContainerID", 1, utf16_bytes("{test-container}"))
                        .child(properties(1_704_067_200, 1_704_153_600))
                        .child(
                            KeySpec::new(INSTANCE)
                                .last_write(filetime_u64(1_704_153_600))
                                .value("FriendlyName", 1, utf16_bytes("Ljnljn Flash"))
                                .value("HardwareID", 7, utf16_bytes("USB\\VID_1234&PID_5678")),
                        ),
                ),
            ),
        ),
    );
    build_hive(&root)
}

fn harness() -> Harness {
    Harness::new(super::plugin)
}

fn run_system(root: &Path) -> lovelycarve_plugin::Result<lovelycarve_plugin::testing::TestRun> {
    harness().run_with_inputs(
        "usbstor",
        Fixture::system("windows", root),
        &["Windows/System32/config/SYSTEM"],
        BTreeMap::new(),
        BTreeMap::new(),
    )
}

#[test]
fn emits_typed_usbstor_records_with_timestamps_and_sources() {
    let fixture = FixtureDir::new("happy");
    fixture.system_hive(&system_hive());
    let run = run_system(&fixture.path).expect("run");

    assert_eq!(run.count("windows.usb.device"), 1);
    let record = run.of_type("windows.usb.device")[0];
    assert_eq!(record.text("device"), Some(DEVICE));
    assert_eq!(record.text("instance"), Some(INSTANCE));
    assert_eq!(record.text("friendly_name"), Some("Ljnljn Flash"));
    assert_eq!(record.text("service"), Some("USBSTOR"));
    assert_eq!(record.text("container_id"), Some("{test-container}"));
    assert_eq!(
        record.text("hardware_id"),
        Some("USB\\VID_1234&PID_5678")
    );
    assert_eq!(record.text("first_install"), Some("2024-01-01T00:00:00Z"));
    assert_eq!(
        record.text("last_arrival"),
        Some("2024-01-02T00:00:00Z")
    );
    assert!(record.text("key_last_write").is_some());
    assert_eq!(record.sources.len(), 1);
    assert!(record.sources[0]
        .path
        .as_deref()
        .unwrap_or("")
        .contains("Windows/System32/config/SYSTEM"));
    assert!(run.summary.as_deref().unwrap_or("").contains("实例 1"));
}

#[test]
fn missing_usbstor_key_is_a_warning_not_an_empty_success() {
    let fixture = FixtureDir::new("missing");
    let hive = build_hive(
        &KeySpec::new("ROOT")
            .child(KeySpec::new("ControlSet001").child(KeySpec::new("Enum"))),
    );
    fixture.system_hive(&hive);
    let run = run_system(&fixture.path).expect("run");

    assert_eq!(run.count("windows.usb.device"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "USBSTOR_NOT_FOUND"));
}

#[test]
fn invalid_hive_is_reported_and_does_not_emit_records() {
    let fixture = FixtureDir::new("invalid");
    fixture.system_hive(b"not a registry hive");
    let run = run_system(&fixture.path).expect("run");

    assert_eq!(run.count("windows.usb.device"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INVALID_SYSTEM_HIVE"));
}

#[test]
fn undeclared_input_pattern_yields_an_explicit_warning() {
    let fixture = FixtureDir::new("empty");
    let run = harness()
        .run_with_inputs(
            "usbstor",
            Fixture::system("windows", &fixture.path),
            &["Windows/System32/config/SYSTEM"],
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .expect("run");

    assert_eq!(run.count("windows.usb.device"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}
