use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRun};

use super::parser::fixtures;
use super::parser::FVE_SIGNATURE;

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
            "ljnljn-bitlocker-{label}-{}-{unique}",
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

fn test_guid(seed: u8) -> [u8; 16] {
    let mut guid = [seed; 16];
    guid[..8].copy_from_slice(&[0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]);
    guid
}

fn build_vhd_image(recovery_guid: Option<[u8; 16]>) -> Vec<u8> {
    let vmks = match recovery_guid {
        Some(guid) => vec![
            fixtures::tpm_vmk(test_guid(0x01)),
            fixtures::recovery_vmk(guid),
        ],
        None => vec![fixtures::tpm_vmk(test_guid(0x02))],
    };
    let volume = fixtures::fve_volume(&vmks);
    let mut image = vec![0_u8; fixtures::TEST_VOLUME_OFFSET as usize];
    image.extend_from_slice(&volume);
    image.resize(8192, 0);
    let footer = fixtures::vhd_footer(3, 1024 * 1024);
    image[8192 - 512..].copy_from_slice(&footer);
    image
}

fn harness() -> Harness {
    Harness::new(super::plugin)
}

fn run_image(name: &str, bytes: &[u8]) -> TestRun {
    let fixture = FixtureDir::new("run");
    let path = fixture.write(name, bytes);
    run_path(&path)
}

fn run_path(path: &Path) -> TestRun {
    harness()
        .run("bitlocker_vhd", Fixture::files(&[path]))
        .expect("file run")
}

fn boolean(record: &lovelycarve_plugin::testing::TestRecord, field: &str) -> Option<bool> {
    record.get(field).and_then(|value| value.as_bool())
}

#[test]
fn vhd_with_recovery_key_reports_format_hits_vmks_and_sources() {
    let guid = test_guid(0xAA);
    let guid_text = super::parser::format_guid(&guid).expect("guid");
    let image = build_vhd_image(Some(guid));
    let run = run_image("synthetic.vhd", &image);

    assert_eq!(run.count("bitlocker.image"), 1);
    let summary = run.of_type("bitlocker.image")[0];
    assert_eq!(summary.text("file_name"), Some("synthetic.vhd"));
    assert_eq!(summary.text("format"), Some("vhd"));
    assert_eq!(summary.text("format_label"), Some("VHD（文件尾 conectix）"));
    assert_eq!(summary.text("format_signature"), Some("conectix"));
    assert_eq!(summary.int("format_signature_offset"), Some(8192 - 512));
    assert_eq!(summary.int("file_size"), Some(image.len() as i64));
    assert_eq!(boolean(&summary, "encrypted"), Some(true));
    assert_eq!(summary.text("encryption_evidence"), Some("fve_signature"));
    assert_eq!(summary.int("signature_count"), Some(2));
    assert_eq!(summary.int("first_signature_offset"), Some(1027));
    assert_eq!(summary.text("recovery_key_guid"), Some(guid_text.as_str()));
    let guids = summary
        .get("recovery_key_guids")
        .expect("guids")
        .as_array()
        .unwrap();
    assert_eq!(guids.len(), 1);
    assert_eq!(guids[0].as_str(), Some(guid_text.as_str()));
    assert_eq!(summary.int("vhd_disk_type"), Some(3));
    assert_eq!(summary.text("vhd_disk_type_label"), Some("动态磁盘"));
    assert_eq!(
        summary.text("vhd_unique_id_hex"),
        Some("11".repeat(16).as_str())
    );
    assert_eq!(summary.sources.len(), 1);
    assert_eq!(summary.sources[0].note.as_deref(), Some("synthetic.vhd"));

    assert_eq!(run.count("bitlocker.hit"), 2);
    let hit = run
        .of_type("bitlocker.hit")
        .into_iter()
        .find(|record| record.int("signature_offset") == Some(1027))
        .expect("boot header hit");
    assert_eq!(hit.text("parse_status"), Some("parsed"));
    assert_eq!(hit.text("parse_basis"), Some("boot_header"));
    assert_eq!(hit.int("metadata_block_offset"), Some(5120));
    assert_eq!(hit.int("vmk_count"), Some(2));
    assert_eq!(hit.int("recovery_key_guid_count"), Some(1));
    assert_eq!(hit.sources[0].offset, Some(1027));
    assert_eq!(hit.sources[0].length, Some(FVE_SIGNATURE.len() as u64));
    assert_eq!(hit.sources[0].note.as_deref(), Some("@0x403"));

    // Both the boot header and the standalone metadata-block copy parse, so
    // the same two VMKs are reported once per hit, as in the v1 plugin.
    assert_eq!(run.count("bitlocker.vmk"), 4);
    let recovery = run
        .of_type("bitlocker.vmk")
        .into_iter()
        .find(|record| boolean(record, "is_recovery_key") == Some(true))
        .expect("recovery vmk");
    assert_eq!(recovery.text("vmk_guid"), Some(guid_text.as_str()));
    assert_eq!(recovery.int("protection_type"), Some(0x0800));
    assert_eq!(recovery.text("protection_label"), Some("恢复密码"));
    assert_eq!(recovery.int("signature_offset"), Some(1027));
    assert_eq!(recovery.int("metadata_block_offset"), Some(5120));
}

#[test]
fn missing_recovery_vmk_is_reported_without_guessing() {
    let image = build_vhd_image(None);
    let run = run_image("synthetic.vhd", &image);

    let summary = run.of_type("bitlocker.image")[0];
    assert_eq!(boolean(&summary, "encrypted"), Some(true));
    let guids = summary
        .get("recovery_key_guids")
        .expect("guids")
        .as_array()
        .unwrap();
    assert!(guids.is_empty());
    let limitations = summary
        .get("limitations")
        .expect("limitations")
        .as_array()
        .unwrap();
    assert!(limitations
        .iter()
        .any(|item| item.as_str().is_some_and(|text| text.contains("0x0800"))));
    assert_eq!(run.count("bitlocker.vmk"), 2);
    assert_eq!(run.count("bitlocker.hit"), 2);
}

#[test]
fn vhdx_without_fve_reports_no_signature_in_the_scanned_range() {
    let mut image = fixtures::vhdx_identifier("synthetic-vhdx");
    image.resize(128 * 1024, 0);
    let run = run_image("synthetic.vhdx", &image);

    let summary = run.of_type("bitlocker.image")[0];
    assert_eq!(summary.text("format"), Some("vhdx"));
    assert_eq!(summary.int("format_signature_offset"), Some(0));
    assert_eq!(boolean(&summary, "encrypted"), Some(false));
    assert_eq!(
        summary.text("encryption_evidence"),
        Some("none_in_scanned_range")
    );
    assert_eq!(summary.text("vhdx_creator"), Some("synthetic-vhdx"));
    assert_eq!(run.count("bitlocker.hit"), 0);
    let limitations = summary
        .get("limitations")
        .expect("limitations")
        .as_array()
        .unwrap();
    assert!(limitations
        .iter()
        .any(|item| item.as_str().is_some_and(|text| text.contains("没有发现"))));
}

#[test]
fn unknown_short_file_is_still_reported_with_limitations() {
    let run = run_image("synthetic.bin", b"not a disk image");

    let summary = run.of_type("bitlocker.image")[0];
    assert_eq!(summary.text("format"), Some("unknown"));
    assert_eq!(boolean(&summary, "encrypted"), Some(false));
    let limitations = summary
        .get("limitations")
        .expect("limitations")
        .as_array()
        .unwrap();
    assert!(limitations.iter().any(|item| item
        .as_str()
        .is_some_and(|text| text.contains("小于 VHD footer"))));
}

#[test]
fn metadata_block_is_recovered_when_boot_relative_offset_does_not_map() {
    let guid = test_guid(0xEE);
    let guid_text = super::parser::format_guid(&guid).expect("guid");
    let volume = fixtures::fve_volume(&[fixtures::recovery_vmk(guid)]);
    let mut image = vec![0_u8; 8192];
    image[1024..1536].copy_from_slice(&volume[..512]);
    let block = &volume[fixtures::TEST_METADATA_RELATIVE_OFFSET as usize..];
    image[6000..6000 + block.len()].copy_from_slice(block);
    let footer = fixtures::vhd_footer(3, 1024 * 1024);
    image[8192 - 512..].copy_from_slice(&footer);

    let run = run_image("dynamic.vhd", &image);
    assert_eq!(run.count("bitlocker.hit"), 2);
    let fallback = run
        .of_type("bitlocker.hit")
        .into_iter()
        .find(|record| record.int("signature_offset") == Some(6000))
        .expect("metadata block hit");
    assert_eq!(fallback.text("parse_status"), Some("parsed"));
    assert_eq!(fallback.text("parse_basis"), Some("metadata_block"));

    let summary = run.of_type("bitlocker.image")[0];
    let guids = summary
        .get("recovery_key_guids")
        .expect("guids")
        .as_array()
        .unwrap();
    assert_eq!(guids.len(), 1);
    assert_eq!(guids[0].as_str(), Some(guid_text.as_str()));
}

#[test]
fn vhdx_with_fve_reports_encryption_and_guid() {
    let guid = test_guid(0xFF);
    let guid_text = super::parser::format_guid(&guid).expect("guid");
    let volume = fixtures::fve_volume(&[fixtures::recovery_vmk(guid)]);
    let mut image = fixtures::vhdx_identifier("synthetic-vhdx");
    image.resize(128 * 1024, 0);
    image[64 * 1024..64 * 1024 + volume.len()].copy_from_slice(&volume);

    let run = run_image("synthetic.vhdx", &image);
    let summary = run.of_type("bitlocker.image")[0];
    assert_eq!(summary.text("format"), Some("vhdx"));
    assert_eq!(boolean(&summary, "encrypted"), Some(true));
    let guids = summary
        .get("recovery_key_guids")
        .expect("guids")
        .as_array()
        .unwrap();
    assert_eq!(guids[0].as_str(), Some(guid_text.as_str()));
    assert_eq!(summary.text("vhdx_creator"), Some("synthetic-vhdx"));
}

#[test]
fn empty_file_selection_returns_an_explicit_warning() {
    let run = harness()
        .run("bitlocker_vhd", Fixture::files(&[]))
        .expect("file run");

    assert_eq!(run.count("bitlocker.image"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}
