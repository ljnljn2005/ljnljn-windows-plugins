//! 注册表通用工件：SOFTWARE 版本、Uninstall 安装项、SYSTEM USBSTOR。
//!
//! 与 SAM 哈希提取共用同一个经过测试的 regf 解析器；只读、边界检查、
//! 不执行检材内容、不联网。文件级分析器接收已提取的单个 hive 文件。

use lovelycarve_plugin::{
    AnalysisResult, Artifact, Attributes, Error, File, FileAnalyzer, Result, ResultColumn,
    ResultNode, Value,
};

use crate::regf::{Hive, RegfError};
use crate::sam_parse::filetime_to_utc;

pub const ANALYZER_VERSION: &str = "ljnljn.windows-registry.software-version";
pub const ANALYZER_UNINSTALL: &str = "ljnljn.windows-registry.uninstall";
pub const ANALYZER_USBSTOR: &str = "ljnljn.windows-registry.usbstor";
pub const ANALYZER_POLICY: &str = "ljnljn.windows-registry.sam-policy";

const MAX_HIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

fn read_file(file: &File) -> Result<Vec<u8>> {
    let size = file.size();
    if size > MAX_HIVE_BYTES {
        return Err(Error::new(
            "RESOURCE_LIMIT",
            format!("hive 大小 {size} 超过 {MAX_HIVE_BYTES} 字节上限"),
        ));
    }
    let mut out = Vec::with_capacity(usize::try_from(size).unwrap_or(0).min(64 * 1024 * 1024));
    let mut offset = 0_u64;
    while offset < size {
        file.context().check_cancelled()?;
        let chunk = file.read(offset, 4 * 1024 * 1024)?;
        if chunk.is_empty() {
            break;
        }
        offset += chunk.len() as u64;
        out.extend_from_slice(&chunk);
    }
    if out.len() as u64 != size {
        return Err(Error::new(
            "SHORT_READ",
            format!("hive 期望 {size} 字节，实际读取 {}", out.len()),
        ));
    }
    Ok(out)
}

fn open_file_hive(file: &File) -> Result<Hive> {
    Hive::open(read_file(file)?).map_err(|error: RegfError| {
        Error::new("INVALID_HIVE", format!("{}: {}", file.name(), error.describe()))
    })
}

fn open_first(hive: &Hive, paths: &[&[&str]]) -> Option<u64> {
    paths.iter().find_map(|path| hive.open_key(path).ok())
}

fn decode_utf16(raw: &[u8]) -> Option<String> {
    if raw.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16(&units).ok()
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn value_text(hive: &Hive, value: &crate::regf::ValueNode) -> Option<String> {
    let data = hive.value_data(value).ok()?;
    match value.data_type {
        1 | 2 => decode_utf16(&data),
        7 => decode_utf16(&data).map(|text| text.replace('\u{0}', " | ")),
        4 if data.len() >= 4 => Some(u32::from_le_bytes(data[..4].try_into().ok()?).to_string()),
        5 if data.len() >= 4 => Some(u32::from_be_bytes(data[..4].try_into().ok()?).to_string()),
        11 if data.len() >= 8 => Some(u64::from_le_bytes(data[..8].try_into().ok()?).to_string()),
        _ => Some(hex(&data)),
    }
}

fn find_value<'a>(
    values: &'a [crate::regf::ValueNode],
    name: &str,
) -> Option<&'a crate::regf::ValueNode> {
    values.iter().find(|value| value.name.eq_ignore_ascii_case(name))
}

fn column(key: &str, label: &str) -> ResultColumn {
    ResultColumn { key: key.into(), label: label.into() }
}

fn source_attributes(source_path: &str, file_id: &str) -> Attributes {
    [
        ("source.path", Value::from(source_path)),
        ("source.file_id", Value::from(file_id)),
    ]
    .into_iter()
    .collect()
}

// ---------------------------------------------------------------------------
// SOFTWARE 版本
// ---------------------------------------------------------------------------

pub fn analyze_version(hive: &Hive, source_path: &str, file_id: &str) -> AnalysisResult {
    let key = open_first(
        hive,
        &[
            &["Microsoft", "Windows NT", "CurrentVersion"],
            &["SOFTWARE", "Microsoft", "Windows NT", "CurrentVersion"],
        ],
    );
    let Some(key) = key else {
        return AnalysisResult {
            summary: Some(format!("{source_path}: 未找到 Microsoft\\Windows NT\\CurrentVersion")),
            ..AnalysisResult::default()
        };
    };
    let values = hive.values(key).unwrap_or_default();
    let mut attributes = source_attributes(source_path, file_id);
    let mut found = Vec::new();
    for name in [
        "ProductName",
        "CurrentVersion",
        "CurrentBuild",
        "CurrentBuildNumber",
        "CSDVersion",
        "BuildLabEx",
        "InstallDate",
    ] {
        if let Some(value) = find_value(&values, name) {
            if let Some(text) = value_text(hive, value) {
                attributes.insert(format!("registry.version.{}", name.to_ascii_lowercase()), text.clone());
                found.push(format!("{name}={text}"));
            }
        }
    }
    let summary = if found.is_empty() {
        format!("{source_path}: CurrentVersion 键存在，但没有可读版本值")
    } else {
        format!("{source_path}: {}", found.join(", "))
    };
    AnalysisResult {
        summary: Some(summary),
        nodes: vec![ResultNode {
            node_type: "registry.software.version".into(),
            name: "SOFTWARE 系统版本".into(),
            columns: vec![
                column("source.path", "来源文件"),
                column("registry.version.productname", "ProductName"),
                column("registry.version.currentversion", "CurrentVersion"),
                column("registry.version.currentbuild", "CurrentBuild"),
                column("registry.version.csdversion", "CSDVersion"),
                column("registry.version.buildlabex", "BuildLabEx"),
            ],
        }],
        artifacts: vec![Artifact {
            artifact_type: "registry.software.version".into(),
            title: "SOFTWARE CurrentVersion".into(),
            value: attributes.get("registry.version.productname").cloned(),
            attributes,
        }],
        ..AnalysisResult::default()
    }
}

// ---------------------------------------------------------------------------
// Uninstall
// ---------------------------------------------------------------------------

pub fn analyze_uninstall(hive: &Hive, source_path: &str, file_id: &str) -> AnalysisResult {
    let mut key = open_first(
        hive,
        &[
            &["Microsoft", "Windows", "CurrentVersion", "Uninstall"],
            &["SOFTWARE", "Microsoft", "Windows", "CurrentVersion", "Uninstall"],
            &["WOW6432Node", "Microsoft", "Windows", "CurrentVersion", "Uninstall"],
            &["SOFTWARE", "WOW6432Node", "Microsoft", "Windows", "CurrentVersion", "Uninstall"],
        ],
    );
    let mut wow = false;
    if key.is_none() {
        key = open_first(
            hive,
            &[
                &["WOW6432Node", "Microsoft", "Windows", "CurrentVersion", "Uninstall"],
                &["SOFTWARE", "WOW6432Node", "Microsoft", "Windows", "CurrentVersion", "Uninstall"],
            ],
        );
        wow = key.is_some();
    }
    let Some(key) = key else {
        return AnalysisResult {
            summary: Some(format!("{source_path}: 未找到 Uninstall 键")),
            ..AnalysisResult::default()
        };
    };
    let subkeys = hive.subkey_cells(key).unwrap_or_default();
    let mut artifacts = Vec::new();
    let mut skipped = 0usize;
    for sub in subkeys {
        let Ok(name) = hive.key_name_at(sub) else { continue };
        let Ok(key_node) = hive.key(sub) else { continue };
        let values = hive.values(sub).unwrap_or_default();
        let Some(display) = find_value(&values, "DisplayName")
            .and_then(|value| value_text(hive, value))
            .filter(|text| !text.trim().is_empty())
        else {
            skipped += 1;
            continue;
        };
        let mut attributes = source_attributes(source_path, file_id);
        attributes.insert("registry.uninstall.key", name.clone());
        attributes.insert("registry.uninstall.displayname", display.clone());
        attributes.insert("registry.uninstall.wow64", wow);
        if let Some(last) = filetime_to_utc(key_node.last_write_time) {
            attributes.insert("registry.uninstall.key_last_write_utc", last);
        }
        for (field, key_name) in [
            ("displayversion", "DisplayVersion"),
            ("publisher", "Publisher"),
            ("installdate", "InstallDate"),
            ("installlocation", "InstallLocation"),
        ] {
            if let Some(value) = find_value(&values, key_name).and_then(|value| value_text(hive, value)) {
                attributes.insert(format!("registry.uninstall.{field}"), value);
            }
        }
        artifacts.push(Artifact {
            artifact_type: "registry.uninstall.entry".into(),
            title: display.clone(),
            value: Some(Value::from(display)),
            attributes,
        });
    }
    let count = artifacts.len();
    AnalysisResult {
        summary: Some(format!(
            "{source_path}: Uninstall 条目 {count} 个（跳过无 DisplayName {skipped} 个）"
        )),
        nodes: vec![ResultNode {
            node_type: "registry.uninstall".into(),
            name: "Uninstall 安装项".into(),
            columns: vec![
                column("source.path", "来源文件"),
                column("registry.uninstall.displayname", "名称"),
                column("registry.uninstall.displayversion", "版本"),
                column("registry.uninstall.installdate", "InstallDate"),
                column("registry.uninstall.publisher", "发布者"),
                column("registry.uninstall.key_last_write_utc", "键最后写入"),
                column("registry.uninstall.wow64", "WOW6432Node"),
            ],
        }],
        artifacts,
        ..AnalysisResult::default()
    }
}

// ---------------------------------------------------------------------------
// USBSTOR
// ---------------------------------------------------------------------------

pub fn analyze_usbstor(hive: &Hive, source_path: &str, file_id: &str) -> AnalysisResult {
    let Some(key) = open_first(
        hive,
        &[
            &["ControlSet001", "Enum", "USBSTOR"],
            &["CurrentControlSet", "Enum", "USBSTOR"],
            &["SYSTEM", "ControlSet001", "Enum", "USBSTOR"],
            &["SYSTEM", "CurrentControlSet", "Enum", "USBSTOR"],
        ],
    ) else {
        return AnalysisResult {
            summary: Some(format!("{source_path}: 未找到 Enum\\USBSTOR 键")),
            ..AnalysisResult::default()
        };
    };
    let devices = hive.subkey_cells(key).unwrap_or_default();
    let device_count = devices.len();
    let mut artifacts = Vec::new();
    let mut instances = 0usize;
    for device_cell in devices {
        let Ok(device_name) = hive.key_name_at(device_cell) else { continue };
        let Ok(device_key) = hive.key(device_cell) else { continue };
        let device_values = hive.values(device_cell).unwrap_or_default();
        let mut base = source_attributes(source_path, file_id);
        base.insert("registry.usbstor.device", device_name.clone());
        if let Some(last) = filetime_to_utc(device_key.last_write_time) {
            base.insert("registry.usbstor.device_last_write_utc", last);
        }
        for (field, name) in [
            ("friendlyname", "FriendlyName"),
            ("devicedesc", "DeviceDesc"),
            ("containerid", "ContainerID"),
            ("hardwareid", "HardwareID"),
        ] {
            if let Some(value) = find_value(&device_values, name).and_then(|value| value_text(hive, value)) {
                base.insert(format!("registry.usbstor.{field}"), value);
            }
        }
        let children = hive.subkey_cells(device_cell).unwrap_or_default();
        if children.is_empty() {
            artifacts.push(Artifact {
                artifact_type: "registry.usbstor.device".into(),
                title: device_name.clone(),
                value: Some(Value::from(device_name)),
                attributes: base,
            });
            continue;
        }
        for instance_cell in children {
            let Ok(instance_name) = hive.key_name_at(instance_cell) else { continue };
            let Ok(instance_key) = hive.key(instance_cell) else { continue };
            instances += 1;
            let mut attributes = base.clone();
            attributes.insert("registry.usbstor.instance", instance_name.clone());
            if let Some(last) = filetime_to_utc(instance_key.last_write_time) {
                attributes.insert("registry.usbstor.instance_last_write_utc", last);
            }
            artifacts.push(Artifact {
                artifact_type: "registry.usbstor.instance".into(),
                title: format!("{device_name}\\{instance_name}"),
                value: Some(Value::from(instance_name)),
                attributes,
            });
        }
    }
    AnalysisResult {
        summary: Some(format!(
            "{source_path}: USBSTOR 设备 {} 个，实例 {instances} 个",
            device_count
        )),
        nodes: vec![ResultNode {
            node_type: "registry.usbstor".into(),
            name: "USBSTOR 设备与实例".into(),
            columns: vec![
                column("source.path", "来源文件"),
                column("registry.usbstor.device", "设备键"),
                column("registry.usbstor.instance", "实例键"),
                column("registry.usbstor.device_last_write_utc", "设备键最后写入"),
                column("registry.usbstor.instance_last_write_utc", "实例最后写入"),
                column("registry.usbstor.friendlyname", "FriendlyName"),
            ],
        }],
        artifacts,
        ..AnalysisResult::default()
    }
}

// ---------------------------------------------------------------------------
// SAM 密码策略（域 Account\F 的 MaxPasswordAge）
// ---------------------------------------------------------------------------

pub fn analyze_policy(hive: &Hive, source_path: &str, file_id: &str) -> AnalysisResult {
    let Some(account) = open_first(hive, &[&["SAM", "Domains", "Account"], &["Domains", "Account"]]) else {
        return AnalysisResult {
            summary: Some(format!("{source_path}: 未找到 Domains\\Account 键")),
            ..AnalysisResult::default()
        };
    };
    let values = hive.values(account).unwrap_or_default();
    let Some(f_value) = find_value(&values, "F") else {
        return AnalysisResult {
            summary: Some(format!("{source_path}: Domains\\Account 不含 F 值")),
            ..AnalysisResult::default()
        };
    };
    let Ok(data) = hive.value_data(f_value) else {
        return AnalysisResult {
            summary: Some(format!("{source_path}: F 值读取失败")),
            ..AnalysisResult::default()
        };
    };
    if data.len() < 0x28 {
        return AnalysisResult {
            summary: Some(format!("{source_path}: F 值仅 {} 字节，不足 0x28", data.len())),
            ..AnalysisResult::default()
        };
    }
    let raw = i64::from_le_bytes(data[0x20..0x28].try_into().unwrap_or([0; 8]));
    let mut attributes = source_attributes(source_path, file_id);
    attributes.insert("registry.sam.policy.max_password_age_raw", raw);
    if raw > 0 {
        // MaxPasswordAge 使用 100ns 单位；天数 = 100ns / (86400 * 10^7)。
        let seconds = raw / 10_000_000;
        let days = raw / 864_000_000_000;
        attributes.insert("registry.sam.policy.max_password_age_seconds", seconds);
        attributes.insert("registry.sam.policy.max_password_age_days", days);
    } else {
        attributes.insert("registry.sam.policy.max_password_age_state", "never_or_unset");
    }
    AnalysisResult {
        summary: Some(format!(
            "{source_path}: MaxPasswordAge raw={raw}{}",
            if raw > 0 { format!(" ({} 天)", raw / 864_000_000_000) } else { " (未设置/永不过期)".to_string() }
        )),
        nodes: vec![ResultNode {
            node_type: "registry.sam.policy".into(),
            name: "SAM 密码策略".into(),
            columns: vec![
                column("source.path", "来源文件"),
                column("registry.sam.policy.max_password_age_raw", "原始 100ns"),
                column("registry.sam.policy.max_password_age_days", "最长留存期(天)"),
                column("registry.sam.policy.max_password_age_state", "状态"),
            ],
        }],
        artifacts: vec![Artifact {
            artifact_type: "registry.sam.policy".into(),
            title: "SAM MaxPasswordAge".into(),
            value: attributes.get("registry.sam.policy.max_password_age_days").cloned(),
            attributes,
        }],
        ..AnalysisResult::default()
    }
}

// ---------------------------------------------------------------------------
// FileAnalyzer 入口
// ---------------------------------------------------------------------------

pub struct SoftwareVersionAnalyzer;
pub struct UninstallAnalyzer;
pub struct UsbStorAnalyzer;
pub struct SamPolicyAnalyzer;

impl FileAnalyzer for SoftwareVersionAnalyzer {
    fn analyzer(&self) -> &str { ANALYZER_VERSION }
    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        let hive = open_file_hive(file)?;
        Ok(analyze_version(&hive, file.name(), file.id()))
    }
}

impl FileAnalyzer for UninstallAnalyzer {
    fn analyzer(&self) -> &str { ANALYZER_UNINSTALL }
    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        let hive = open_file_hive(file)?;
        Ok(analyze_uninstall(&hive, file.name(), file.id()))
    }
}

impl FileAnalyzer for UsbStorAnalyzer {
    fn analyzer(&self) -> &str { ANALYZER_USBSTOR }
    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        let hive = open_file_hive(file)?;
        Ok(analyze_usbstor(&hive, file.name(), file.id()))
    }
}

impl FileAnalyzer for SamPolicyAnalyzer {
    fn analyzer(&self) -> &str { ANALYZER_POLICY }
    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        let hive = open_file_hive(file)?;
        Ok(analyze_policy(&hive, file.name(), file.id()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhive::{build_hive, KeySpec};

    fn utf16(text: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for unit in text.encode_utf16() {
            out.extend_from_slice(&unit.to_le_bytes());
        }
        out.push(0);
        out.push(0);
        out
    }

    fn with_value(mut key: KeySpec, name: &str, text: &str) -> KeySpec {
        key.values.push((name.to_string(), 1, utf16(text)));
        key
    }

    #[test]
    fn version_reads_current_version_values() {
        let current = with_value(
            with_value(
                with_value(KeySpec::new("CurrentVersion"), "ProductName", "Windows 7 Ultimate"),
                "CurrentVersion",
                "6.1",
            ),
            "CurrentBuildNumber",
            "7601",
        );
        let hive = Hive::open(build_hive(
            &KeySpec::new("SOFTWARE")
                .child(KeySpec::new("Microsoft").child(KeySpec::new("Windows NT").child(current))),
        ))
        .expect("hive");
        let result = analyze_version(&hive, "SOFTWARE", "file-1");
        assert!(result.summary.as_deref().unwrap_or("").contains("Windows 7 Ultimate"));
        assert!(result.artifacts.len() == 1);
        let value = result.artifacts[0].attributes.get("registry.version.currentversion").unwrap();
        assert_eq!(value.as_str(), Some("6.1"));
    }

    #[test]
    fn uninstall_enumerates_display_name_and_skips_entries_without_it() {
        let hive = Hive::open(build_hive(
            &KeySpec::new("SOFTWARE").child(
                KeySpec::new("Microsoft").child(
                    KeySpec::new("Windows").child(
                        KeySpec::new("CurrentVersion").child(
                            KeySpec::new("Uninstall")
                                .child(with_value(
                                    with_value(KeySpec::new("AppA"), "DisplayName", "App A"),
                                    "DisplayVersion",
                                    "1.2.3",
                                ))
                                .child(KeySpec::new("NoName").value("Publisher", 1, utf16("X"))),
                        ),
                    ),
                ),
            ),
        ))
        .expect("hive");
        let result = analyze_uninstall(&hive, "SOFTWARE", "file-2");
        assert_eq!(result.artifacts.len(), 1);
        assert_eq!(
            result.artifacts[0].attributes.get("registry.uninstall.displayversion").unwrap().as_str(),
            Some("1.2.3")
        );
    }

    #[test]
    fn usbstor_enumerates_device_and_instance_keys() {
        let hive = Hive::open(build_hive(
            &KeySpec::new("SYSTEM").child(
                KeySpec::new("ControlSet001").child(
                    KeySpec::new("Enum").child(
                        KeySpec::new("USBSTOR").child(
                            KeySpec::new("Disk&Ven_SanDisk&Prod_Ultra")
                                .child(KeySpec::new("4C530001310423109141&0")),
                        ),
                    ),
                ),
            ),
        ))
        .expect("hive");
        let result = analyze_usbstor(&hive, "SYSTEM", "file-3");
        assert_eq!(result.artifacts.len(), 1);
        assert_eq!(
            result.artifacts[0].attributes.get("registry.usbstor.device").unwrap().as_str(),
            Some("Disk&Ven_SanDisk&Prod_Ultra")
        );
        assert_eq!(
            result.artifacts[0].attributes.get("registry.usbstor.instance").unwrap().as_str(),
            Some("4C530001310423109141&0")
        );
    }

    #[test]
    fn sam_policy_reads_max_password_age_days() {
        let mut f = vec![0u8; 0x28];
        let days = 42i64;
        f[0x20..0x28].copy_from_slice(&(days * 864_000_000_000i64).to_le_bytes());
        let hive = Hive::open(build_hive(
            &KeySpec::new("SAM").child(
                KeySpec::new("SAM").child(
                    KeySpec::new("Domains").child(
                        KeySpec::new("Account").value("F", 3, f),
                    ),
                ),
            ),
        ))
        .expect("hive");
        let result = analyze_policy(&hive, "SAM", "file-policy");
        assert_eq!(result.artifacts.len(), 1);
        assert_eq!(
            result.artifacts[0]
                .attributes
                .get("registry.sam.policy.max_password_age_days")
                .and_then(|value| value.as_i64()),
            Some(days)
        );
    }

    #[test]
    fn missing_keys_return_summary_not_panic() {
        let hive = Hive::open(build_hive(&KeySpec::new("SOFTWARE"))).expect("hive");
        assert!(analyze_version(&hive, "SOFTWARE", "x").artifacts.is_empty());
        assert!(analyze_uninstall(&hive, "SOFTWARE", "x").artifacts.is_empty());
        assert!(analyze_usbstor(&hive, "SOFTWARE", "x").artifacts.is_empty());
    }
}
