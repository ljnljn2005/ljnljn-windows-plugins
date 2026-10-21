use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRecord, TestRun};

use super::crypto::md4::nt_hash_of_password;
use super::sam_parse;
use super::testhive::{
    build_hive, lsa_classes, sample_with_account, system_root, user_f, utf16_bytes, KeySpec, Sample,
};

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
            "ljnljn-registry-{label}-{}-{unique}",
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

    fn config(&self, name: &str, bytes: &[u8]) {
        self.write(&format!("Windows/System32/config/{name}"), bytes);
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

fn filetime_u64(unix_seconds: u64) -> u64 {
    (unix_seconds + 11_644_473_600) * 10_000_000
}

fn utc(filetime: u64) -> String {
    super::time::filetime_timestamp(filetime)
        .expect("timestamp")
        .as_str()
        .to_owned()
}

fn run_system(analyzer: &str, root: &Path, inputs: &[&str]) -> TestRun {
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

fn run_file(analyzer: &str, path: &Path) -> TestRun {
    Harness::new(super::plugin)
        .run(analyzer, Fixture::files(&[path]))
        .expect("run")
}

fn write_sample(fixture: &FixtureDir, sample: &Sample) {
    fixture.config("SAM", &sample.sam_bytes);
    fixture.config("SYSTEM", &sample.system_bytes);
}

fn account_named<'a>(run: &'a TestRun, name: &str) -> &'a TestRecord {
    run.of_type("windows.sam.account")
        .into_iter()
        .find(|record| record.text("name") == Some(name))
        .unwrap_or_else(|| panic!("missing account {name}"))
}

#[test]
fn sam_pair_emits_nt_hash_last_login_and_sources() {
    let password = "Passw0rd!测试";
    let nt = nt_hash_of_password(password);
    let sample = sample_with_account("alice", 1001, &nt, &[0u8; 16]);
    let fixture = FixtureDir::new("sam");
    write_sample(&fixture, &sample);
    let run = run_system(
        "sam_accounts_system",
        &fixture.path,
        &["Windows/System32/config/SAM", "Windows/System32/config/SYSTEM"],
    );

    let bootkey = &run.of_type("windows.sam.bootkey")[0];
    assert_eq!(
        bootkey.text("bootkey"),
        Some(sam_parse::hex_lower(&sample.bootkey).as_str())
    );
    assert!(bootkey.text("classes").unwrap_or("").contains("JD="));
    assert_eq!(bootkey.sources.len(), 2);

    let account = account_named(&run, "alice");
    assert_eq!(account.int("rid"), Some(1001));
    assert_eq!(
        account.text("nt_hash"),
        Some(sam_parse::hex_lower(&nt).as_str())
    );
    assert_eq!(account.text("nt_state"), Some("present"));
    assert_eq!(account.text("hash_algorithm"), Some("nt"));
    assert_eq!(account.int("login_count"), Some(7));
    assert_eq!(
        account.text("last_login"),
        Some(utc(132_000_000_000_000_000).as_str())
    );
    assert_eq!(account.int("last_login_raw"), Some(132_000_000_000_000_000));
    assert_eq!(
        account.get("decrypt_ok").and_then(|value| value.as_bool()),
        Some(true)
    );
    assert_eq!(account.text("lm_hash"), None);
    assert_eq!(account.text("lm_state"), Some("zero_placeholder"));
    assert_eq!(account.sources.len(), 2);
    assert!(account
        .values
        .values()
        .all(|value| value.as_str() != Some(password)));
    assert!(run
        .summary
        .as_deref()
        .unwrap_or("")
        .contains("解密校验通过 1"));
}

#[test]
fn zero_hash_is_a_marked_placeholder_not_a_hash() {
    let sample = sample_with_account("disabled", 1002, &[0u8; 16], &[0u8; 16]);
    let fixture = FixtureDir::new("zero");
    write_sample(&fixture, &sample);
    let run = run_system(
        "sam_accounts_system",
        &fixture.path,
        &["Windows/System32/config/SAM", "Windows/System32/config/SYSTEM"],
    );
    let account = account_named(&run, "disabled");
    assert_eq!(account.text("nt_hash"), None);
    assert_eq!(account.text("nt_state"), Some("zero_placeholder"));
    assert_eq!(account.text("lm_state"), Some("zero_placeholder"));
    assert!(account.text("nt_reason").unwrap_or("").contains("全零"));
}

#[test]
fn lm_unsaved_is_distinct_from_a_zero_placeholder() {
    let sample = sample_with_account(
        "nt_only",
        1003,
        &nt_hash_of_password("ntonly"),
        &[],
    );
    let fixture = FixtureDir::new("lm-unsaved");
    write_sample(&fixture, &sample);
    let run = run_system(
        "sam_accounts_system",
        &fixture.path,
        &["Windows/System32/config/SAM", "Windows/System32/config/SYSTEM"],
    );
    let account = account_named(&run, "nt_only");
    assert_eq!(account.text("nt_state"), Some("present"));
    assert_eq!(account.text("lm_state"), Some("not_saved"));
    assert!(account.text("lm_reason").unwrap_or("").contains("未保存"));
}

#[test]
fn wrong_bootkey_marks_hashes_unavailable_instead_of_guessing() {
    let nt = nt_hash_of_password("Wr0ngPerm");
    let mut sample = sample_with_account("perm", 1007, &nt, &[0u8; 16]);
    let mut wrong = sample.bootkey;
    wrong[0] ^= 0xFF;
    sample.system_bytes = build_hive(&system_root(&lsa_classes(&wrong)));
    let fixture = FixtureDir::new("wrong-bootkey");
    write_sample(&fixture, &sample);
    let run = run_system(
        "sam_accounts_system",
        &fixture.path,
        &["Windows/System32/config/SAM", "Windows/System32/config/SYSTEM"],
    );
    let account = account_named(&run, "perm");
    assert_eq!(
        account.get("decrypt_ok").and_then(|value| value.as_bool()),
        Some(false)
    );
    assert_eq!(account.text("nt_hash"), None);
    assert_eq!(account.text("nt_state"), Some("unavailable"));
    assert!(account.text("nt_reason").unwrap_or("").contains("解密"));
}

#[test]
fn missing_system_hive_is_reported_not_treated_as_empty_success() {
    let sample = sample_with_account("alice", 1001, &nt_hash_of_password("x"), &[0u8; 16]);
    let fixture = FixtureDir::new("missing-system");
    fixture.config("SAM", &sample.sam_bytes);
    let run = run_system(
        "sam_accounts_system",
        &fixture.path,
        &["Windows/System32/config/SAM", "Windows/System32/config/SYSTEM"],
    );
    assert_eq!(run.count("windows.sam.account"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "MISSING_SYSTEM_HIVE"));
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "NO_SAM_SYSTEM_PAIR"));
}

#[test]
fn evidence_scope_pairs_sam_and_system_per_volume() {
    let first = sample_with_account("alice", 1001, &nt_hash_of_password("a"), &[0u8; 16]);
    let second = sample_with_account("bob", 1002, &nt_hash_of_password("b"), &[0u8; 16]);
    let volume_one = FixtureDir::new("pair-1");
    let volume_two = FixtureDir::new("pair-2");
    write_sample(&volume_one, &first);
    write_sample(&volume_two, &second);
    let run = Harness::new(super::plugin)
        .run_with_inputs(
            "sam_accounts",
            Fixture::evidence(&[("part:1", &volume_one.path), ("part:2", &volume_two.path)]),
            &[
                "*/Windows/System32/config/SAM",
                "*/Windows/System32/config/SYSTEM",
            ],
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .expect("run");
    assert_eq!(run.count("windows.sam.account"), 2);
    assert!(account_named(&run, "alice").sources[0].root.as_deref() == Some("part:1"));
    assert!(account_named(&run, "bob").sources[0].root.as_deref() == Some("part:2"));
}

#[test]
fn domain_sid_is_composed_from_the_names_default_value() {
    let mut default = vec![0u8; 0x34];
    default[0x30..0x34].copy_from_slice(&1000u32.to_le_bytes());
    default.extend_from_slice(&[1, 4, 0, 0, 0, 0, 0, 5]);
    for sub in [21u32, 1, 2, 3] {
        default.extend_from_slice(&sub.to_le_bytes());
    }
    let members = KeySpec::new("Users").child(
        KeySpec::new("000003E8").value("F", 3, user_f("alice", 1000, 0, 0)),
    );
    let names = KeySpec::new("Names").child(KeySpec::new("alice").value("", 3, default));
    let account = KeySpec::new("Account").child(members).child(names);
    let hive = super::regf::Hive::open(build_hive(
        &KeySpec::new("SAM").child(
            KeySpec::new("SAM").child(KeySpec::new("Domains").child(account)),
        ),
    ))
    .expect("hive");
    let domain = sam_parse::domain_sid(&hive).expect("domain SID");
    assert_eq!(domain.to_string(), "S-1-5-21-1-2-3");
    let keys = sam_parse::hash_keys(&[0u8; 16], None);
    let mut notes = Vec::new();
    let accounts = sam_parse::extract_accounts(&hive, &keys, &mut notes).expect("accounts");
    assert_eq!(accounts.len(), 1);
    assert_eq!(
        accounts[0].account_sid.as_deref(),
        Some("S-1-5-21-1-2-3-1000")
    );
}

#[test]
fn software_version_analyzer_emits_typed_values() {
    let current = KeySpec::new("CurrentVersion").last_write(filetime_u64(1_704_153_600))
        .value("ProductName", 1, utf16("Windows 11 Pro"))
        .value("CurrentVersion", 1, utf16("10.0"))
        .value("CurrentBuild", 1, utf16("22631"))
        .value("CurrentBuildNumber", 1, utf16("22631"))
        .value("CSDVersion", 1, utf16(""))
        .value("BuildLabEx", 1, utf16("22621.1.amd64fre"))
        .value("InstallDate", 4, 1_620_038_668u32.to_le_bytes().to_vec());
    let hive = build_hive(
        &KeySpec::new("SOFTWARE").child(
            KeySpec::new("Microsoft")
                .child(KeySpec::new("Windows NT").child(current)),
        ),
    );
    let fixture = FixtureDir::new("version");
    let path = fixture.write("SOFTWARE", &hive);
    let run = run_file("software_version_file", &path);
    let record = &run.of_type("windows.software.version")[0];
    assert_eq!(record.text("product_name"), Some("Windows 11 Pro"));
    assert_eq!(record.text("current_version"), Some("10.0"));
    assert_eq!(record.text("current_build_number"), Some("22631"));
    assert_eq!(record.text("build_lab_ex"), Some("22621.1.amd64fre"));
    assert_eq!(record.text("install_date"), Some("1620038668"));
    assert!(run.warnings.is_empty(), "{:?}", run.warnings);
}

#[test]
fn uninstall_entries_skip_unnamed_and_honor_wow64() {
    let uninstall = KeySpec::new("Uninstall")
        .child(
            KeySpec::new("AppA")
                .last_write(filetime_u64(1_704_067_200))
                .value("DisplayName", 1, utf16("App A"))
                .value("DisplayVersion", 1, utf16("1.2.3"))
                .value("Publisher", 1, utf16("Vendor"))
                .value("InstallDate", 1, utf16("20240102"))
                .value("InstallLocation", 1, utf16("C:/Apps/A")),
        )
        .child(KeySpec::new("NoName").value("Publisher", 1, utf16("X")));
    let hive = build_hive(
        &KeySpec::new("SOFTWARE").child(
            KeySpec::new("Microsoft")
                .child(KeySpec::new("Windows").child(KeySpec::new("CurrentVersion").child(uninstall))),
        ),
    );
    let fixture = FixtureDir::new("uninstall");
    let path = fixture.write("SOFTWARE", &hive);
    let run = run_file("uninstall_file", &path);
    let records = run.of_type("windows.registry.uninstall");
    assert_eq!(records.len(), 1);
    let record = records[0];
    assert_eq!(record.text("name"), Some("App A"));
    assert_eq!(record.text("display_version"), Some("1.2.3"));
    assert_eq!(record.text("install_date"), Some("20240102"));
    assert_eq!(record.text("key_last_write"), Some("2024-01-01T00:00:00Z"));
    assert_eq!(
        record.get("wow64").and_then(|value| value.as_bool()),
        Some(false)
    );
    assert!(run.summary.as_deref().unwrap_or("").contains("跳过无 DisplayName 1"));

    let wow = build_hive(
        &KeySpec::new("SOFTWARE").child(
            KeySpec::new("WOW6432Node").child(
                KeySpec::new("Microsoft").child(
                    KeySpec::new("Windows").child(
                        KeySpec::new("CurrentVersion").child(
                            KeySpec::new("Uninstall").child(
                                KeySpec::new("App32")
                                    .value("DisplayName", 1, utf16("App 32")),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    );
    let path = fixture.write("SOFTWARE-wow", &wow);
    let run = run_file("uninstall_file", &path);
    let record = &run.of_type("windows.registry.uninstall")[0];
    assert_eq!(record.text("name"), Some("App 32"));
    assert_eq!(
        record.get("wow64").and_then(|value| value.as_bool()),
        Some(true)
    );
}

#[test]
fn usbstor_emits_device_and_instance_times() {
    let install = filetime_u64(1_704_067_200);
    let arrival = filetime_u64(1_704_153_600);
    let properties = KeySpec::new("Properties").child(
        KeySpec::new("83da6326-97a6-4088-9453-a1923f573b29")
            .child(KeySpec::new("0064").value("", 3, install.to_le_bytes().to_vec()))
            .child(KeySpec::new("0066").value("", 3, arrival.to_le_bytes().to_vec())),
    );
    let device = KeySpec::new("Disk&Ven_Ljnljn&Prod_UsbTest&Rev_1.00")
        .last_write(install)
        .value("FriendlyName", 1, utf16("Ljnljn USB Test"))
        .value("DeviceDesc", 1, utf16("USB Mass Storage Device"))
        .value("Service", 1, utf16("USBSTOR"))
        .value("ContainerID", 1, utf16("{test-container}"))
        .child(properties)
        .child(
            KeySpec::new("0123456789ABCDEF")
                .last_write(arrival)
                .value("FriendlyName", 1, utf16("Ljnljn Flash"))
                .value("HardwareID", 7, utf16("USB\\VID_1234&PID_5678")),
        );
    let hive = build_hive(
        &KeySpec::new("SYSTEM").child(
            KeySpec::new("ControlSet001")
                .child(KeySpec::new("Enum").child(KeySpec::new("USBSTOR").child(device))),
        ),
    );
    let fixture = FixtureDir::new("usbstor");
    let path = fixture.write("SYSTEM", &hive);
    let run = run_file("usbstor_file", &path);
    let record = &run.of_type("windows.registry.usbstor")[0];
    assert_eq!(record.text("device"), Some("Disk&Ven_Ljnljn&Prod_UsbTest&Rev_1.00"));
    assert_eq!(record.text("instance"), Some("0123456789ABCDEF"));
    assert_eq!(record.text("friendly_name"), Some("Ljnljn Flash"));
    assert_eq!(record.text("service"), Some("USBSTOR"));
    assert_eq!(record.text("container_id"), Some("{test-container}"));
    assert_eq!(record.text("hardware_id"), Some("USB\\VID_1234&PID_5678"));
    assert_eq!(record.text("first_install"), Some("2024-01-01T00:00:00Z"));
    assert_eq!(record.text("last_arrival"), Some("2024-01-02T00:00:00Z"));
    assert_eq!(record.text("device_last_write"), Some("2024-01-01T00:00:00Z"));
    assert_eq!(record.text("instance_last_write"), Some("2024-01-02T00:00:00Z"));
}

#[test]
fn device_without_instances_still_has_a_record() {
    let hive = build_hive(
        &KeySpec::new("SYSTEM").child(
            KeySpec::new("ControlSet001").child(
                KeySpec::new("Enum").child(
                    KeySpec::new("USBSTOR")
                        .child(KeySpec::new("Disk&Ven_Empty").value("FriendlyName", 1, utf16("Empty"))),
                ),
            ),
        ),
    );
    let fixture = FixtureDir::new("usbstor-empty");
    let path = fixture.write("SYSTEM", &hive);
    let run = run_file("usbstor_file", &path);
    let record = &run.of_type("windows.registry.usbstor")[0];
    assert_eq!(record.text("device"), Some("Disk&Ven_Empty"));
    assert_eq!(record.text("instance"), Some(""));
    assert!(record.title.contains("Disk&Ven_Empty"));
}

#[test]
fn password_policy_reads_max_password_age_and_never_state() {
    let mut f = vec![0u8; 0x28];
    let days = 42i64;
    f[0x20..0x28].copy_from_slice(&(days * 864_000_000_000i64).to_le_bytes());
    let hive = build_hive(
        &KeySpec::new("SAM").child(
            KeySpec::new("Domains")
                .child(KeySpec::new("Account").value("F", 3, f)),
        ),
    );
    let fixture = FixtureDir::new("policy");
    let path = fixture.write("SAM", &hive);
    let run = run_file("password_policy_file", &path);
    let record = &run.of_type("windows.registry.policy")[0];
    assert_eq!(record.int("max_password_age_raw"), Some(days * 864_000_000_000));
    assert_eq!(record.int("max_password_age_seconds"), Some(days * 86_400));
    assert_eq!(record.int("max_password_age_days"), Some(days));
    assert_eq!(record.text("state"), Some("set"));

    let hive = build_hive(
        &KeySpec::new("SAM").child(
            KeySpec::new("Domains")
                .child(KeySpec::new("Account").value("F", 3, vec![0u8; 0x28])),
        ),
    );
    let path = fixture.write("SAM-never", &hive);
    let run = run_file("password_policy_file", &path);
    let record = &run.of_type("windows.registry.policy")[0];
    assert_eq!(record.int("max_password_age_raw"), Some(0));
    assert_eq!(record.text("state"), Some("never_or_unset"));
    assert_eq!(record.int("max_password_age_days"), None);
}

#[test]
fn invalid_hive_warns_and_emits_no_records() {
    let fixture = FixtureDir::new("invalid");
    let path = fixture.write("SOFTWARE", b"not a registry hive");
    let run = run_file("software_version_file", &path);
    assert_eq!(run.count("windows.software.version"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INVALID_HIVE"));
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "NO_USABLE_HIVE"));
}

#[test]
fn missing_capability_keys_are_warnings_not_empty_successes() {
    let fixture = FixtureDir::new("missing-keys");
    let hive = build_hive(&KeySpec::new("SOFTWARE"));
    let path = fixture.write("SOFTWARE", &hive);
    let run = run_file("uninstall_file", &path);
    assert_eq!(run.count("windows.registry.uninstall"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "UNINSTALL_KEY_NOT_FOUND"));

    let run = run_file("usbstor_file", &path);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "USBSTOR_NOT_FOUND"));

    let run = run_file("password_policy_file", &path);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "SAM_POLICY_NOT_FOUND"));
}

