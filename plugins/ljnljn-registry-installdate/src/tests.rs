//! 纯解析单元测试：正常输入、缺失 / 损坏 / 边界、来源标识。
//!
//! 所有样例都由 [`crate::synth`] 在内存里合成，不读取任何真实检材；
//! 期望时间用**手工计算**的常量（`MANUAL_*`），不在测试里调用被测的时间函数。

use crate::extract::{analyze_hive, InstallState, NoteLevel, SourceInfo};
use crate::regf::{Hive, SliceReader};
use crate::render::{self, ART_AUX_VALUE, ART_EVIDENCE, ART_HIVE, ART_INSTALL_DATE, ART_KEY, ART_WARNING};
use crate::synth::{
    build_dword_hive, current_version_values, current_version_with, software_tree, HeaderPatch,
    HiveBuilder, IndexKind, KeySpec, NameEncoding, ValueSpec, REG_BINARY, REG_DWORD,
    REG_DWORD_BIG_ENDIAN, REG_MULTI_SZ, REG_SZ,
};
use crate::time::Plausibility;
use crate::TARGET_VALUE;

/// 来源快照里的取值：1620038668 → 2021-05-03T10:44:28Z。
///
/// 手工核对：1620038668 / 86400 = 18750 天，余 38668 秒 = 10h 44m 28s…
/// 但 18750 天对应的日期是 2021-05-02（1970-01-01 起算），所以
/// 2021-05-02T10:44:28Z 与 2021-05-03T10:44:28Z 都“看起来对”。
/// 结论由独立实现 target/callepoch.rs（只实现 Howard Hinnant 的 days_from_civil）
/// 交叉核对：civil(1620038668/86400) = 2021-5-3，余 33868 秒 = 9h 24m 28s。
const MANUAL_2021: u64 = 1_620_038_668;
const MANUAL_2021_UTC: &str = "2021-05-03T10:44:28Z";
/// 1325750400 → 2012-01-05T08:00:00Z（1325750400/86400 = 15344 天余 28800 秒 = 8h）。
const MANUAL_2012_UTC: &str = "2012-01-05T08:00:00Z";

fn file_info(name: &str) -> SourceInfo {
    SourceInfo::file(name)
}

fn report_of(bytes: &[u8]) -> crate::extract::HiveReport {
    analyze_hive(SliceReader::new(bytes), file_info("SOFTWARE"))
}

fn artifact<'a>(
    result: &'a lovelycarve_plugin::AnalysisResult,
    artifact_type: &str,
) -> &'a lovelycarve_plugin::Artifact {
    result
        .artifacts
        .iter()
        .find(|artifact| artifact.artifact_type == artifact_type)
        .unwrap_or_else(|| panic!("缺少 artifact {artifact_type}"))
}

fn attr<'a>(
    artifact: &'a lovelycarve_plugin::Artifact,
    key: &str,
) -> Option<String> {
    crate::attr_text(artifact, key)
}

fn warn_texts(result: &lovelycarve_plugin::AnalysisResult) -> Vec<String> {
    result
        .artifacts
        .iter()
        .filter(|artifact| {
            // 只统计真告警：覆盖范围/限制类是 Info 级别的说明，不算告警。
            artifact.artifact_type == ART_WARNING
                && crate::attr_text(artifact, "installdate.level").as_deref() == Some("warning")
        })
        .map(|artifact| artifact.title.clone())
        .collect()
}

// ---------------------------------------------------------------------------
// 正常输入
// ---------------------------------------------------------------------------

#[test]
fn dword_install_date_parses_to_manual_utc() {
    let bytes = build_dword_hive(MANUAL_2021 as u32);
    let report = report_of(&bytes);
    assert!(report.header.accepted, "{:?}", report.header_error);
    assert_eq!(report.header.version.as_deref(), Some("1.5"));
    assert_eq!(report.header.checksum_state, "match");
    assert_eq!(report.header.file_name.as_deref(), Some("SOFTWARE"));
    assert!(report.key_exists());
    assert_eq!(
        report.key.as_ref().unwrap().resolved_path.as_deref(),
        Some(r"Microsoft\Windows NT\CurrentVersion")
    );

    let date = &report.install_date;
    assert_eq!(date.state, InstallState::Parsed);
    assert_eq!(date.raw_type.as_deref(), Some("REG_DWORD"));
    assert_eq!(date.raw_value, Some(MANUAL_2021));
    assert_eq!(date.hex.as_deref(), Some("0x608fd40c"));
    assert_eq!(date.utc.as_deref(), Some(MANUAL_2021_UTC));
    assert_eq!(date.plausibility, Some(Plausibility::Plausible));
    let raw_display = date.raw_display.clone().unwrap();
    assert!(raw_display.starts_with("1620038668"));
    assert!(raw_display.contains("本地时区未知"));
    // 诱饵：同名的值在 Microsoft\Windows NT\Run 里，不能被当成目标。
    assert_ne!(date.raw_value, Some(1_000_000_000));
    // 辅助值
    // 辅助值按值名（大小写不敏感）扫描整个值列表，存在才输出。
    let names = report
        .aux_values
        .iter()
        .map(|aux| aux.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        names,
        vec![
            "ProductName",
            "CurrentBuild",
            "CurrentBuildNumber",
            "CurrentVersion",
            "CurrentMajorVersionNumber",
            "CurrentMinorVersionNumber",
            "DisplayVersion",
            "EditionID",
            "ProductId",
            "UBR",
        ]
    );
    let product = report
        .aux_values
        .iter()
        .find(|aux| aux.name == "ProductName")
        .unwrap();
    assert_eq!(product.text, "Windows 10 Pro");
    assert_eq!(product.value_type, "REG_SZ");
    // InstallDate 不能重复出现在辅助值里
    assert!(!names.iter().any(|name| name.eq_ignore_ascii_case(TARGET_VALUE)));
}

#[test]
fn dword_result_artifacts_carry_values_and_source() {
    let bytes = build_dword_hive(MANUAL_2021 as u32);
    let report = report_of(&bytes);
    let result = render::build_result(&report);
    assert!(result.summary.as_deref().unwrap().contains(MANUAL_2021_UTC));
    assert_eq!(result.timeline.len(), 0);

    let hive = artifact(&result, ART_HIVE);
    assert_eq!(attr(hive, "installdate.regf_valid").as_deref(), Some("true"));
    assert_eq!(attr(hive, "installdate.magic_ok").as_deref(), Some("true"));
    assert_eq!(attr(hive, "installdate.version").as_deref(), Some("1.5"));
    assert_eq!(
        attr(hive, "installdate.file_size").as_deref(),
        Some(bytes.len().to_string().as_str())
    );
    assert_eq!(attr(hive, "source.path").as_deref(), Some("SOFTWARE"));
    assert_eq!(attr(hive, "source.root").as_deref(), Some("file"));

    let key = artifact(&result, ART_KEY);
    assert_eq!(attr(key, "installdate.key_exists").as_deref(), Some("true"));
    assert!(attr(key, "installdate.key_cell_offset")
        .unwrap()
        .starts_with("0x"));

    let date = artifact(&result, ART_INSTALL_DATE);
    assert_eq!(attr(date, "installdate.state").as_deref(), Some("parsed"));
    assert_eq!(
        attr(date, "installdate.raw_value").as_deref(),
        Some(MANUAL_2021.to_string().as_str())
    );
    assert_eq!(
        attr(date, "installdate.raw_hex").as_deref(),
        Some("0x608fd40c")
    );
    assert_eq!(attr(date, "installdate.utc").as_deref(), Some(MANUAL_2021_UTC));
    assert_eq!(
        attr(date, "installdate.raw_type").as_deref(),
        Some("REG_DWORD")
    );
    assert!(attr(date, "installdate.raw_display")
        .unwrap()
        .contains("本地时区未知"));
    assert!(attr(date, "installdate.vk_offset").unwrap().starts_with("0x"));
    assert!(date
        .attributes
        .contains_key("installdate.vk_file_offset"));

    let evidence = artifact(&result, ART_EVIDENCE);
    let locator = attr(evidence, "installdate.locator").unwrap();
    assert!(locator.contains("vk@cell 0x"));
    assert!(locator.contains("REG_DWORD"));

    let aux = result
        .artifacts
        .iter()
        .filter(|artifact| artifact.artifact_type == ART_AUX_VALUE)
        .count();
    assert_eq!(aux, 10);
    assert!(result
        .artifacts
        .iter()
        .any(|artifact| artifact.artifact_type == crate::render::ART_LIMITATION));
    // 每个 artifact 都必须带来源属性
    for artifact in &result.artifacts {
        if artifact.artifact_type == crate::render::ART_LIMITATION {
            continue;
        }
        assert!(
            artifact.attributes.contains_key("source.path"),
            "{} 缺少 source.path",
            artifact.artifact_type
        );
        assert!(
            artifact.attributes.contains_key("source.root"),
            "{} 缺少 source.root",
            artifact.artifact_type
        );
    }
}

#[test]
fn evidence_locator_offsets_point_at_the_value_cell() {
    let bytes = build_dword_hive(MANUAL_2021 as u32);
    let report = report_of(&bytes);
    let vk_cell = report.install_date.vk_cell.expect("vk cell");
    let file_offset = report.install_date.vk_file_offset.unwrap();
    // vk_cell 是「带 4 字节长度前缀的 cell 偏移」，file_offset 是同一位置的绝对文件偏移。
    assert_eq!(file_offset, 0x1000 + u64::from(vk_cell));
    let at = file_offset as usize;
    let size_prefix =
        i32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    assert!(size_prefix < 0, "值单元应当是已分配状态（负长度前缀）");
    assert_eq!(&bytes[at + 4..at + 6], b"vk");
    // vk 载荷起始 + 0x0c 是类型字段。
    let type_at = at + 4 + 0x0c;
    let value_type = u32::from_le_bytes(bytes[type_at..type_at + 4].try_into().unwrap());
    assert_eq!(value_type, REG_DWORD);
}

#[test]
fn string_install_date_in_decimal_parses_to_same_utc() {
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::sz("InstallDate", &MANUAL_2021.to_string()))),
    );
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
    let report = report_of(&bytes);
    assert!(report.key_exists());
    let date = &report.install_date;
    assert_eq!(date.state, InstallState::Parsed);
    assert_eq!(date.raw_type.as_deref(), Some("REG_SZ"));
    assert_eq!(date.raw_value, Some(MANUAL_2021));
    assert_eq!(date.utc.as_deref(), Some(MANUAL_2021_UTC));
    assert!(!date.text_hex_notation);
    // REG_SZ 的十六进制原值是 UTF-16LE 字节，不是时间数值
    assert_eq!(date.raw_hex.as_deref(), Some("31 00 36 00 32 00 30 00 30 00 33 00 38 00 36 00 36 00 38 00 00 00"));
}

#[test]
fn string_with_padding_and_hex_notation_is_handled() {
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::sz("InstallDate", "  1620038668 \0"))),
    );
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
    assert_eq!(report_of(&bytes).install_date.utc.as_deref(), Some(MANUAL_2021_UTC));

    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::sz("InstallDate", "0x608FD40C"))),
    );
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
    let report = report_of(&bytes);
    assert_eq!(report.install_date.raw_value, Some(MANUAL_2021));
    assert_eq!(report.install_date.utc.as_deref(), Some(MANUAL_2021_UTC));
    assert!(report.install_date.text_hex_notation);
}

#[test]
fn other_manual_epoch_instants_match() {
    let bytes = build_dword_hive(1_325_750_400);
    let report = report_of(&bytes);
    assert_eq!(report.install_date.utc.as_deref(), Some(MANUAL_2012_UTC));
    // 1325750400 = 0x4F055880（独立脚本换算：15344 天 + 28800 秒 = 2012-01-05T08:00:00Z）
    assert_eq!(report.install_date.hex.as_deref(), Some("0x4f055880"));
}

#[test]
fn case_differences_in_key_and_value_names_still_match() {
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::dword("INSTALLDATE", 1_325_750_400))),
    );
    let windows_nt = KeySpec::new("Windows NT")
        .child(key)
        .with_index(IndexKind::Lh);
    let microsoft = KeySpec::new("microsoft")
        .with_index(IndexKind::Li)
        .child(windows_nt);
    let tree = KeySpec::new("SOFTWARE").child(microsoft);
    let (bytes, _) = HiveBuilder::new().build(&tree, &HeaderPatch::default());
    let report = report_of(&bytes);
    assert!(report.key_exists(), "{:?}", report.notes);
    assert_eq!(
        report.key.as_ref().unwrap().resolved_path.as_deref(),
        Some(r"microsoft\Windows NT\CurrentVersion")
    );
    assert_eq!(report.install_date.utc.as_deref(), Some(MANUAL_2012_UTC));
    assert_eq!(
        report.install_date.value_name.as_deref(),
        Some("INSTALLDATE")
    );
}

#[test]
fn non_compressed_utf16_key_names_parse() {
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::dword("InstallDate", 1_325_750_400))),
    );
    let windows_nt = KeySpec::new("Windows NT")
        .with_encoding(NameEncoding::Utf16)
        .with_index(IndexKind::Ri)
        .child(key);
    let microsoft = KeySpec::new("Microsoft")
        .with_encoding(NameEncoding::Utf16)
        .child(windows_nt);
    let tree = KeySpec::new("SOFTWARE").child(microsoft);
    let (bytes, _) = HiveBuilder::new().build(&tree, &HeaderPatch::default());
    let report = report_of(&bytes);
    assert!(report.key_exists(), "{:?}", report.notes);
    assert_eq!(report.install_date.utc.as_deref(), Some(MANUAL_2012_UTC));
}

#[test]
fn big_data_install_date_string_round_trips() {
    // 超过 16344 字节的 REG_SZ（尾部为空白，数字在开头），强制走 db 大值分段。
    let mut text = MANUAL_2021.to_string();
    text.push_str(&" ".repeat(20_000));
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::sz("InstallDate", &text).with_big_data())),
    );
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
    let report = report_of(&bytes);
    assert_eq!(report.install_date.raw_value, Some(MANUAL_2021));
    assert_eq!(report.install_date.big_data, Some(true));
    assert_eq!(report.install_date.utc.as_deref(), Some(MANUAL_2021_UTC));
}

#[test]
fn root_key_offset_written_as_cell_header_also_parses() {
    // 手工把根键偏移改成“带前缀的 cell 头”（另一种写法），解析器应两解兼容。
    let bytes = build_dword_hive(MANUAL_2021 as u32);
    let hive = Hive::open(SliceReader::new(&bytes)).expect("open");
    let root = hive.root_key().expect("root");
    let mut patched = bytes.clone();
    // cell 头偏移 = 载荷偏移 - 4（合成器把根偏移写成载荷位置）
    let cell = root.cell_offset - 4;
    patched[0x24..0x28].copy_from_slice(&cell.to_le_bytes());
    // 让校验和重新自洽：compute_checksum 已包含当前存储值，写入它即整体异或为 0。
    let computed = crate::regf::compute_checksum(&patched[..0x1000]);
    patched[0x1fc..0x200].copy_from_slice(&computed.to_le_bytes());
    let report = report_of(&patched);
    assert!(report.header.accepted, "{:?}", report.header_error);
    assert!(report.key_exists());
    assert_eq!(report.install_date.utc.as_deref(), Some(MANUAL_2021_UTC));
}

// ---------------------------------------------------------------------------
// 缺失
// ---------------------------------------------------------------------------

#[test]
fn missing_install_date_reports_missing_but_keeps_aux_values() {
    let key = KeySpec::with_values("CurrentVersion", current_version_values());
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
    let report = report_of(&bytes);
    assert!(report.key_exists());
    assert_eq!(report.install_date.state, InstallState::Missing);
    assert!(!report.install_date.present);
    assert_eq!(report.install_date.raw_value, None);
    assert!(!report.aux_values.is_empty());
    assert!(report
        .notes
        .iter()
        .any(|note| note.kind == "value" && note.text.contains("没有名为 InstallDate 的值")));
    let result = render::build_result(&report);
    let date = artifact(&result, ART_INSTALL_DATE);
    assert_eq!(attr(date, "installdate.state").as_deref(), Some("missing"));
}

#[test]
fn missing_target_key_reports_the_missing_segment() {
    // Microsoft 存在，但下面没有 Windows NT（只有 Windows\CurrentVersion 干扰项）。
    let decoy = KeySpec::new("Windows")
        .child(KeySpec::with_values("CurrentVersion", vec![ValueSpec::dword("InstallDate", 5)]));
    let tree = KeySpec::new("SOFTWARE").child(KeySpec::new("Microsoft").child(decoy));
    let (bytes, _) = HiveBuilder::new().build(&tree, &HeaderPatch::default());
    let report = report_of(&bytes);
    assert!(!report.key_exists());
    let key = report.key.as_ref().unwrap();
    assert_eq!(key.missing_segment.as_deref(), Some("Windows NT"));
    assert_eq!(key.resolved_path.as_deref(), Some("Microsoft"));
    assert_eq!(report.install_date.state, InstallState::Missing);
    let result = render::build_result(&report);
    let key_artifact = artifact(&result, ART_KEY);
    assert_eq!(
        attr(key_artifact, "installdate.key_exists").as_deref(),
        Some("false")
    );
    assert_eq!(
        attr(key_artifact, "installdate.missing_segment").as_deref(),
        Some("Windows NT")
    );
}

#[test]
fn empty_hive_root_without_children_is_missing_not_error() {
    let tree = KeySpec::new("SOFTWARE");
    let (bytes, _) = HiveBuilder::new().build(&tree, &HeaderPatch::default());
    let report = report_of(&bytes);
    assert!(report.header.accepted);
    assert!(!report.key_exists());
    assert_eq!(
        report.key.as_ref().unwrap().missing_segment.as_deref(),
        Some("Microsoft")
    );
}

// ---------------------------------------------------------------------------
// 边界
// ---------------------------------------------------------------------------

#[test]
fn zero_install_date_keeps_raw_value_and_warns() {
    let report = report_of(&build_dword_hive(0));
    let date = &report.install_date;
    assert_eq!(date.state, InstallState::Unusable);
    assert_eq!(date.raw_value, Some(0));
    assert_eq!(date.utc, None);
    assert_eq!(date.plausibility, Some(Plausibility::Zero));
    assert!(date.detail.as_deref().unwrap().contains("未写入"));
    assert!(date.raw_display.as_deref().unwrap().contains("本地时区未知"));
    assert!(report
        .notes
        .iter()
        .any(|note| note.kind == "time" && note.level == NoteLevel::Warning));
}

#[test]
fn implausible_but_representable_value_is_flagged() {
    // 86400 = 1970-01-02T00:00:00Z：能换算，但明显不是安装时间。
    let report = report_of(&build_dword_hive(86_400));
    let date = &report.install_date;
    assert_eq!(date.utc.as_deref(), Some("1970-01-02T00:00:00Z"));
    assert_eq!(date.plausibility, Some(Plausibility::Implausible));
    assert_eq!(date.state, InstallState::Unusable);
    assert!(date.detail.as_deref().unwrap().contains("可疑"));
}

#[test]
fn out_of_range_value_keeps_raw_and_warns_without_utc() {
    // 0xFFFFFFFF = 4294967295 → 2106-02-07T06:28:15Z：ISO8601 能表示，
    // 但远晚于任何合理安装时间，因此给出 UTC 的同时标为可疑（不猜测、不吞掉原值）。
    let report = report_of(&build_dword_hive(u32::MAX));
    let date = &report.install_date;
    assert_eq!(date.raw_value, Some(u64::from(u32::MAX)));
    assert_eq!(date.hex.as_deref(), Some("0xffffffff"));
    assert_eq!(date.utc.as_deref(), Some("2106-02-07T06:28:15Z"));
    assert_eq!(date.state, InstallState::Unusable);
    assert_eq!(date.plausibility, Some(Plausibility::Implausible));
    assert!(date.detail.as_deref().unwrap().contains("可疑"));
}

#[test]
fn unrepresentable_seconds_keep_raw_but_have_no_utc() {
    // 9999-12-31T23:59:59Z 之后没有 4 位年份可写，ISO8601 直接给不出时间。
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::sz("InstallDate", "253402300800"))),
    );
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
    let report = report_of(&bytes);
    let date = &report.install_date;
    assert_eq!(date.raw_value, Some(253_402_300_800));
    assert_eq!(date.utc, None);
    assert_eq!(date.state, InstallState::Unusable);
    assert_eq!(date.plausibility, Some(Plausibility::Unrepresentable));
    assert!(date.detail.as_deref().unwrap().contains("超出"));
}

#[test]
fn big_endian_dword_is_unsupported_but_raw_is_preserved() {
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::raw(
            "InstallDate",
            REG_DWORD_BIG_ENDIAN,
            // 4 字节大端：REG_DWORD_BIG_ENDIAN 就是 4 字节值，必须截到 u32 再转。
            (MANUAL_2021 as u32).to_be_bytes().to_vec(),
        ))),
    );
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
    let report = report_of(&bytes);
    let date = &report.install_date;
    assert_eq!(date.state, InstallState::Unusable);
    assert_eq!(date.raw_type.as_deref(), Some("REG_DWORD_BIG_ENDIAN"));
    assert_eq!(date.raw_value, None);
    assert_eq!(
        date.raw_hex.as_deref(),
        Some("60 8f d4 0c")
    );
    assert!(date.detail.as_deref().unwrap().contains("不支持"));
}

#[test]
fn binary_multi_sz_and_junk_string_are_unsupported() {
    for spec in [
        ValueSpec::binary("InstallDate", &[0x00, 0x01, 0x02, 0x03, 0x04]),
        ValueSpec::multi_sz("InstallDate", &["2021", "05"]),
        ValueSpec::sz("InstallDate", "2021-05-03"),
        ValueSpec::sz("InstallDate", ""),
        ValueSpec::raw("InstallDate", REG_BINARY, vec![]),
    ] {
        let key = KeySpec::with_values(
            "CurrentVersion",
            current_version_with(Some(spec.clone())),
        );
        let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
        let report = report_of(&bytes);
        let date = &report.install_date;
        assert_eq!(date.state, InstallState::Unusable, "{spec:?}");
        assert_eq!(date.raw_value, None, "{spec:?}");
        assert!(date.detail.is_some(), "{spec:?}");
    }
}

#[test]
fn truncated_dword_data_is_reported_not_guessed() {
    // 声明长度 2 的 REG_DWORD：取不出 32 位原值。
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(
            ValueSpec::raw("InstallDate", REG_DWORD, vec![0x8c, 0xb8]).with_declared_len(2),
        )),
    );
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
    let report = report_of(&bytes);
    assert_eq!(report.install_date.raw_value, None);
    assert_eq!(report.install_date.state, InstallState::Unusable);
}

#[test]
fn declared_length_beyond_data_cell_marks_truncated_and_warns() {
    // 声明 4096 字节，但数据单元只放了 12 字节：保留已读部分并告警。
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(
            ValueSpec::sz("InstallDate", &MANUAL_2021.to_string()).with_declared_len(4096),
        )),
    );
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
    let report = report_of(&bytes);
    assert!(report
        .notes
        .iter()
        .any(|note| note.text.contains("声明") && note.text.contains("只读到")));
    // 已读部分仍是完整数字串（UTF-16 截断在 12 字节内），时间照常算出。
    assert_eq!(report.install_date.raw_value, Some(MANUAL_2021));
}

#[test]
fn duplicate_install_date_values_take_first_and_warn() {
    let mut values = current_version_with(Some(ValueSpec::dword("InstallDate", 1_325_750_400)));
    values.push(ValueSpec::dword("installdate", 1_000_000_000));
    let key = KeySpec::with_values("CurrentVersion", values);
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
    let report = report_of(&bytes);
    assert_eq!(report.install_date.utc.as_deref(), Some(MANUAL_2012_UTC));
    assert!(report
        .notes
        .iter()
        .any(|note| note.text.contains("大小写不同")));
}

#[test]
fn multiple_current_version_keys_are_disambiguated() {
    let clean = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::dword("InstallDate", 1_325_750_400))),
    );
    let decoy_install = KeySpec::with_values(
        "CURRENTVERSION",
        current_version_with(Some(ValueSpec::dword("InstallDate", 1_066_600_000))),
    );
    let windows_nt = KeySpec::new("Windows NT")
        .child(clean)
        .child(decoy_install.clone());
    let tree = KeySpec::new("SOFTWARE")
        .child(KeySpec::new("Microsoft").child(windows_nt))
        // 第二个 Microsoft 分支（大小写不同），路径 Key 不唯一，必须告警
        .child(KeySpec::new("microsoft").child(KeySpec::new("Windows NT").child(decoy_install)));
    let (bytes, _) = HiveBuilder::new().build(&tree, &HeaderPatch::default());
    let report = report_of(&bytes);
    // 同一父键下两个等价子键名：取枚举顺序第一个并告警
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.text.contains("大小写不同但等价")),
        "{:?}",
        report.notes
    );
    // 另一处 Microsoft 大小写不同：同样告警
    assert!(
        report
            .notes
            .iter()
            .any(|note| note.text.contains("等价于「Microsoft」")),
        "{:?}",
        report.notes
    );
    assert_eq!(report.install_date.state, InstallState::Parsed);
    let result = render::build_result(&report);
    assert_eq!(
        attr(artifact(&result, ART_INSTALL_DATE), "installdate.state").as_deref(),
        Some("parsed")
    );
    assert!(result
        .artifacts
        .iter()
        .any(|artifact| artifact.artifact_type == ART_WARNING));
}

#[test]
fn value_name_aliases_do_not_change_lookup() {
    // 名字相近但不相等（InstallDatex）不应命中。
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::dword("InstallDatex", 1_325_750_400))),
    );
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &HeaderPatch::default());
    let report = report_of(&bytes);
    assert_eq!(report.install_date.state, InstallState::Missing);
}

// ---------------------------------------------------------------------------
// 损坏 / 头部
// ---------------------------------------------------------------------------

#[test]
fn any_header_check_failure_stops_parsing() {
    let good = build_dword_hive(MANUAL_2021 as u32);
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("魔数错误", {
            let mut bytes = good.clone();
            bytes[0..4].copy_from_slice(b"REGF");
            bytes
        }),
        ("文件类型为事务日志", {
            let mut bytes = good.clone();
            bytes[0x1c..0x20].copy_from_slice(&1_u32.to_le_bytes());
            bytes
        }),
        ("不支持的版本", {
            let mut bytes = good.clone();
            bytes[0x18..0x1c].copy_from_slice(&9_u32.to_le_bytes());
            bytes
        }),
        ("校验和不一致", {
            let mut bytes = good.clone();
            bytes[0x1fc..0x200].copy_from_slice(&0xdead_beef_u32.to_le_bytes());
            bytes
        }),
        ("bins 长度不是 0x1000 倍数", {
            let mut bytes = good.clone();
            bytes[0x28..0x2c].copy_from_slice(&0x1234_u32.to_le_bytes());
            let checksum = crate::regf::compute_checksum(&bytes[..0x1000]);
            bytes[0x1fc..0x200].copy_from_slice(&checksum.to_le_bytes());
            bytes
        }),
        ("hbin 头被破坏", {
            let mut bytes = good.clone();
            bytes[0x1000..0x1004].copy_from_slice(b"HBIN");
            let checksum = crate::regf::compute_checksum(&bytes[..0x1000]);
            bytes[0x1fc..0x200].copy_from_slice(&checksum.to_le_bytes());
            bytes
        }),
        ("头声明的 bins 超出文件", {
            let mut bytes = good.clone();
            bytes[0x28..0x2c].copy_from_slice(&0x9000_u32.to_le_bytes());
            let checksum = crate::regf::compute_checksum(&bytes[..0x1000]);
            bytes[0x1fc..0x200].copy_from_slice(&checksum.to_le_bytes());
            bytes
        }),
        ("文件截断到 0x800", good[..0x800].to_vec()),
        ("空文件", Vec::new()),
    ];
    for (label, bytes) in cases {
        let report = report_of(&bytes);
        assert!(!report.header.accepted, "{label}");
        assert!(report.header_error.is_some(), "{label}");
        assert!(report.key.is_none(), "{label}");
        assert_eq!(report.install_date.state, InstallState::Missing, "{label}");
        let result = render::build_result(&report);
        let hive = artifact(&result, ART_HIVE);
        assert_eq!(attr(hive, "installdate.regf_valid").as_deref(), Some("false"), "{label}");
        assert!(hive.attributes.contains_key("installdate.error_code"), "{label}");
        assert!(result.summary.as_deref().unwrap().contains("未解析"), "{label}");
    }
}

#[test]
fn trailing_truncation_of_payload_is_detected_by_declared_length() {
    // 头部完整、bins 数据区被截掉尾部（文件比头部声明短）。
    let bytes = build_dword_hive(MANUAL_2021 as u32);
    let report = report_of(&bytes[..bytes.len() - 512]);
    assert!(!report.header.accepted);
    assert!(report
        .notes
        .iter()
        .any(|note| note.text.contains("截断")));
}

#[test]
fn zero_checksum_is_treated_as_unwritten_placeholder() {
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::dword("InstallDate", 1_325_750_400))),
    );
    let patch = HeaderPatch {
        checksum: Some(0),
        ..HeaderPatch::default()
    };
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &patch);
    let report = report_of(&bytes);
    assert!(report.header.accepted);
    assert_eq!(report.header.checksum_state, "placeholder_zero");
    assert_eq!(report.install_date.utc.as_deref(), Some(MANUAL_2012_UTC));
    assert!(report
        .notes
        .iter()
        .any(|note| note.text.contains("校验和为 0")));
}

#[test]
fn inconsistent_sequences_warn_but_still_parse() {
    let key = KeySpec::with_values(
        "CurrentVersion",
        current_version_with(Some(ValueSpec::dword("InstallDate", 1_325_750_400))),
    );
    let patch = HeaderPatch {
        sequences: Some((9, 8)),
        ..HeaderPatch::default()
    };
    let (bytes, _) = HiveBuilder::new().build(&software_tree(key), &patch);
    let report = report_of(&bytes);
    assert!(report.header.accepted);
    assert!(report
        .notes
        .iter()
        .any(|note| note.text.contains("序列号不一致")));
}

#[test]
fn corrupted_value_cell_is_an_error_not_a_panic() {
    let bytes = build_dword_hive(MANUAL_2021 as u32);
    let hive = Hive::open(SliceReader::new(&bytes)).expect("open");
    let root = hive.root_key().expect("root");
    let (microsofts, _) = hive.lookup_subkey_all(&root, "Microsoft");
    let microsoft = microsofts.first().expect("Microsoft");
    let (windows_nts, _) = hive.lookup_subkey_all(microsoft, "Windows NT");
    let windows_nt = windows_nts.first().expect("Windows NT");
    let (cv, _) = hive.lookup_subkey_all(windows_nt, "CurrentVersion");
    let cv = cv.first().expect("CurrentVersion");
    let offsets = hive.value_offsets(cv).expect("value list");
    let install = offsets
        .iter()
        .map(|offset| hive.read_value(*offset).expect("value"))
        .find(|value| value.name == "InstallDate")
        .expect("InstallDate");
    // 把 vk 签名改成 "xx"：读取必须报错而不是 panic。
    let mut patched = bytes.clone();
    let at = 0x1000 + install.vk_cell as usize;
    patched[at..at + 4].copy_from_slice(&(-20_i32).to_le_bytes());
    patched[at + 4..at + 6].copy_from_slice(b"xx");
    let patched_report = report_of(&patched);
    assert!(!patched_report.header.accepted || patched_report.install_date.raw_value.is_none());
}

#[test]
fn subkey_list_pointing_outside_bins_is_reported() {
    // 目标键的子键列表偏移指向一个不存在的单元：不得 panic。
    let bytes = build_dword_hive(MANUAL_2021 as u32);
    let hive = Hive::open(SliceReader::new(&bytes)).expect("open");
    let root = hive.root_key().expect("root");
    let (microsofts, _) = hive.lookup_subkey_all(&root, "Microsoft");
    let microsoft = microsofts.first().expect("Microsoft");
    let mut patched = bytes.clone();
    // 覆盖 Microsoft 的 nk 子键列表偏移（nk 载荷 + 0x1c）为一个越界值。
    let payload = 0x1000 + microsoft.cell_offset as usize + 4;
    patched[payload + 0x1c..payload + 0x20].copy_from_slice(&0x7fff_fff0_u32.to_le_bytes());
    let report = report_of(&patched);
    assert!(report.header.accepted);
    assert!(!report.key_exists());
    assert!(!report.notes.is_empty());
}

// ---------------------------------------------------------------------------
// 来源标识
// ---------------------------------------------------------------------------

#[test]
fn source_identification_is_carried_into_every_artifact() {
    let bytes = build_dword_hive(MANUAL_2021 as u32);
    let report = analyze_hive(
        SliceReader::new(&bytes),
        SourceInfo::volume("part:2", "Windows/System32/config/SOFTWARE"),
    );
    let result = render::build_result(&report);
    for artifact in &result.artifacts {
        if artifact.artifact_type == crate::render::ART_LIMITATION {
            continue;
        }
        assert_eq!(
            attr(artifact, "source.path").as_deref(),
            Some("Windows/System32/config/SOFTWARE")
        );
        assert_eq!(attr(artifact, "source.root").as_deref(), Some("part:2"));
        assert_eq!(attr(artifact, "installdate.source").as_deref(), Some("volume"));
    }
    let evidence = artifact(&result, ART_EVIDENCE);
    assert!(attr(evidence, "installdate.locator")
        .unwrap()
        .contains(r"Microsoft\Windows NT\CurrentVersion"));
    assert_eq!(
        attr(evidence, "installdate.hive_file_size").as_deref(),
        Some(bytes.len().to_string().as_str())
    );
}

#[test]
fn single_file_source_marks_root_as_file() {
    let bytes = build_dword_hive(1_325_750_400);
    let result = render::build_result(&report_of(&bytes));
    for artifact in &result.artifacts {
        if artifact.artifact_type == crate::render::ART_LIMITATION {
            continue;
        }
        assert_eq!(attr(artifact, "source.root").as_deref(), Some("file"));
        assert_eq!(attr(artifact, "source.path").as_deref(), Some("SOFTWARE"));
    }
}

#[test]
fn limitations_are_reported_for_every_analysis() {
    let result = render::build_result(&report_of(&build_dword_hive(1_325_750_400)));
    let limitations = result
        .artifacts
        .iter()
        .filter(|artifact| artifact.artifact_type == crate::render::ART_LIMITATION)
        .count();
    assert_eq!(limitations, crate::extract::LIMITATIONS.len());
    let texts = result
        .artifacts
        .iter()
        .filter(|artifact| artifact.artifact_type == crate::render::ART_LIMITATION)
        .map(|artifact| attr(artifact, "installdate.detail").unwrap())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(texts.contains("时区推断"));
    assert!(texts.contains("SYSTEM hive"));
    assert!(texts.contains("安装日志"));
}

#[test]
fn result_nodes_and_artifact_types_are_consistent() {
    let result = render::build_result(&report_of(&build_dword_hive(1_325_750_400)));
    assert_eq!(result.nodes.len(), crate::artifact_types().len());
    for node in &result.nodes {
        assert!(crate::artifact_types().contains(&node.node_type.as_str()));
    }
    assert!(!result.summary.as_deref().unwrap().is_empty());
    let warnings = warn_texts(&result);
    assert!(warnings.is_empty(), "正常样例不应有告警：{warnings:?}");
}

#[test]
fn identity_constants_are_consistent_with_expected_names() {
    assert_eq!(crate::ANALYZER, "ljnljn.registry-installdate");
    assert_eq!(
        crate::PLUGIN_ID,
        "org.ljnljn.registry-installdate"
    );
    assert!(crate::identity_matches(crate::PLUGIN_ID, "0.1.0"));
    assert!(!crate::identity_matches("org.other", "0.1.0"));
    assert!(!crate::identity_matches(crate::PLUGIN_ID, "9.9.9"));
}

#[test]
fn dword_value_types_are_propagated() {
    assert_eq!(crate::ValueType::from_raw(REG_DWORD).name(), "REG_DWORD");
    assert_eq!(crate::ValueType::from_raw(REG_SZ).name(), "REG_SZ");
    assert_eq!(
        crate::ValueType::from_raw(REG_DWORD_BIG_ENDIAN).name(),
        "REG_DWORD_BIG_ENDIAN"
    );
    assert_eq!(crate::ValueType::from_raw(REG_MULTI_SZ).name(), "REG_MULTI_SZ");
    assert_eq!(crate::ValueType::from_raw(0x999).name(), "REG_UNKNOWN(0x999)");
    assert_eq!(crate::ValueType::from_raw(REG_BINARY).name(), "REG_BINARY");
}
