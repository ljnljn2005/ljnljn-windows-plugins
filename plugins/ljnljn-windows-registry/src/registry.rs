//! Typed SOFTWARE / Uninstall / USBSTOR / SAM policy extraction.
//!
//! These analyzers share the bounds-checked regf parser with the SAM hash
//! extraction. Every function takes the run and the input file so the
//! emitted records keep their evidence source; missing keys are warnings,
//! never silent empty successes.

use lovelycarve_plugin::{FileRef, Result, Run};

use crate::regf::{Hive, ValueNode};
use crate::time::filetime_timestamp;
use crate::{
    SamPolicyRecord, SoftwareVersionRecord, UninstallRecord, UsbDeviceRecord,
};

/// Largest hive read into memory.
pub const MAX_HIVE_BYTES: u64 = 1024 * 1024 * 1024;

/// USBSTOR device property set carrying first-install / last-arrival.
const DEVICE_PROPERTIES: &str = "83da6326-97a6-4088-9453-a1923f573b29";
const PROPERTY_FIRST_INSTALL: &str = "0064";
const PROPERTY_LAST_ARRIVAL: &str = "0066";

pub struct UninstallStats {
    entries: usize,
    skipped: usize,
}

pub struct UsbStats {
    devices: usize,
    instances: usize,
}

/// Reads and parses one input as a hive. Unreadable or invalid hives are
/// recorded as warnings and yield `None`.
pub fn read_hive(run: &Run, file: &FileRef) -> Result<Option<Hive>> {
    let bytes = match file.read_all(MAX_HIVE_BYTES) {
        Ok(bytes) => bytes,
        Err(error) => {
            run.warn_file(file, &error.code, error.message.clone())?;
            return Ok(None);
        }
    };
    match Hive::open(bytes) {
        Ok(hive) => Ok(Some(hive)),
        Err(error) => {
            run.warn_file(
                file,
                "INVALID_HIVE",
                format!("{}: regf 解析失败（{}）", file.name(), error.describe()),
            )?;
            Ok(None)
        }
    }
}

pub fn label(file: &FileRef) -> String {
    file.root_path()
        .or_else(|| file.view_path())
        .unwrap_or_else(|| file.name())
        .to_owned()
}

pub fn open_first(hive: &Hive, paths: &[&[&str]]) -> Option<u64> {
    paths.iter().find_map(|path| hive.open_key(path).ok())
}

fn child_ci(hive: &Hive, parent: u64, name: &str) -> Option<u64> {
    hive.subkey_cells(parent).ok()?.into_iter().find(|cell| {
        hive.key_name_at(*cell)
            .map(|child| child.eq_ignore_ascii_case(name))
            .unwrap_or(false)
    })
}

fn decode_utf16(raw: &[u8]) -> Option<String> {
    if raw.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let text = String::from_utf16(&units).ok()?;
    Some(text.trim_end_matches('\0').to_owned())
}

pub fn value_text(hive: &Hive, value: &ValueNode) -> Option<String> {
    let data = hive.value_data(value).ok()?;
    match value.data_type {
        1 | 2 => decode_utf16(&data),
        7 => decode_utf16(&data).map(|text| text.replace('\u{0}', " | ")),
        4 if data.len() >= 4 => Some(
            u64::from(u32::from_le_bytes(data[..4].try_into().ok()?)).to_string(),
        ),
        5 if data.len() >= 4 => Some(
            u64::from(u32::from_be_bytes(data[..4].try_into().ok()?)).to_string(),
        ),
        11 if data.len() >= 8 => {
            Some(u64::from_le_bytes(data[..8].try_into().ok()?).to_string())
        }
        _ => Some(crate::time::hex_lower(&data)),
    }
}

fn find_value<'a>(values: &'a [ValueNode], name: &str) -> Option<&'a ValueNode> {
    values
        .iter()
        .find(|value| value.name.eq_ignore_ascii_case(name))
}

fn first_text(values: &[ValueNode], hive: &Hive, name: &str) -> Option<String> {
    find_value(values, name).and_then(|value| value_text(hive, value))
}

pub fn analyze_version(run: &Run, file: &FileRef, hive: &Hive) -> Result<Option<String>> {
    let label = label(file);
    let Some(key) = open_first(
        hive,
        &[
            &["Microsoft", "Windows NT", "CurrentVersion"],
            &["SOFTWARE", "Microsoft", "Windows NT", "CurrentVersion"],
        ],
    ) else {
        run.warn_file(
            file,
            "VERSION_KEY_NOT_FOUND",
            format!("{label}: 未找到 Microsoft\\Windows NT\\CurrentVersion"),
        )?;
        return Ok(None);
    };
    let values = hive.values(key).unwrap_or_default();
    let read = |name: &str| first_text(&values, hive, name);
    let product_name = read("ProductName").unwrap_or_else(|| "(未提供)".to_owned());
    let record = SoftwareVersionRecord {
        product_name: product_name.clone(),
        current_version: read("CurrentVersion"),
        current_build: read("CurrentBuild"),
        current_build_number: read("CurrentBuildNumber"),
        csd_version: read("CSDVersion"),
        build_lab_ex: read("BuildLabEx"),
        install_date: read("InstallDate"),
    };
    run.record(&record)
        .from(file)
        .note(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion")
        .emit()?;
    Ok(Some(format!("{label}: {product_name}")))
}

pub fn analyze_uninstall(run: &Run, file: &FileRef, hive: &Hive) -> Result<Option<String>> {
    let label = label(file);
    let mut wow = None;
    let key = open_first(
        hive,
        &[
            &["Microsoft", "Windows", "CurrentVersion", "Uninstall"],
            &["SOFTWARE", "Microsoft", "Windows", "CurrentVersion", "Uninstall"],
        ],
    )
    .or_else(|| {
        wow = Some(true);
        open_first(
            hive,
            &[
                &["WOW6432Node", "Microsoft", "Windows", "CurrentVersion", "Uninstall"],
                &[
                    "SOFTWARE",
                    "WOW6432Node",
                    "Microsoft",
                    "Windows",
                    "CurrentVersion",
                    "Uninstall",
                ],
            ],
        )
    });
    let Some(key) = key else {
        run.warn_file(
            file,
            "UNINSTALL_KEY_NOT_FOUND",
            format!("{label}: 未找到 Uninstall 键"),
        )?;
        return Ok(None);
    };
    let wow = wow.unwrap_or(false);
    let subkeys = hive.subkey_cells(key).unwrap_or_default();
    let mut stats = UninstallStats {
        entries: 0,
        skipped: 0,
    };
    for sub in subkeys {
        run.check_cancelled()?;
        let Ok(name) = hive.key_name_at(sub) else {
            continue;
        };
        let Ok(key_node) = hive.key(sub) else {
            continue;
        };
        let values = hive.values(sub).unwrap_or_default();
        let Some(display) = first_text(&values, hive, "DisplayName")
            .filter(|text| !text.trim().is_empty())
        else {
            stats.skipped += 1;
            continue;
        };
        let record = UninstallRecord {
            name: display.clone(),
            key: name,
            display_version: first_text(&values, hive, "DisplayVersion"),
            publisher: first_text(&values, hive, "Publisher"),
            install_date: first_text(&values, hive, "InstallDate"),
            install_location: first_text(&values, hive, "InstallLocation"),
            key_last_write: filetime_timestamp(key_node.last_write_time),
            wow64: wow,
        };
        run.record(&record)
            .from(file)
            .note(if wow {
                r"SOFTWARE\WOW6432Node\...\Uninstall"
            } else {
                r"SOFTWARE\...\Uninstall"
            })
            .emit()?;
        stats.entries += 1;
    }
    Ok(Some(format!(
        "{label}: Uninstall 条目 {} 个（跳过无 DisplayName {} 个）",
        stats.entries, stats.skipped
    )))
}

pub fn analyze_usbstor(run: &Run, file: &FileRef, hive: &Hive) -> Result<Option<String>> {
    let label = label(file);
    let Some(root) = open_first(
        hive,
        &[
            &["ControlSet001", "Enum", "USBSTOR"],
            &["CurrentControlSet", "Enum", "USBSTOR"],
            &["SYSTEM", "ControlSet001", "Enum", "USBSTOR"],
            &["SYSTEM", "CurrentControlSet", "Enum", "USBSTOR"],
        ],
    ) else {
        run.warn_file(
            file,
            "USBSTOR_NOT_FOUND",
            format!("{label}: 未找到 Enum\\USBSTOR"),
        )?;
        return Ok(None);
    };
    let device_cells = hive.subkey_cells(root).unwrap_or_default();
    let mut stats = UsbStats {
        devices: device_cells.len(),
        instances: 0,
    };
    for device_cell in device_cells {
        run.check_cancelled()?;
        let Ok(device_name) = hive.key_name_at(device_cell) else {
            continue;
        };
        let Ok(device_key) = hive.key(device_cell) else {
            continue;
        };
        let device_values = hive.values(device_cell).unwrap_or_default();
        let device_last_write = filetime_timestamp(device_key.last_write_time);
        let mut instances = Vec::new();
        for child in hive.subkey_cells(device_cell).unwrap_or_default() {
            let Ok(name) = hive.key_name_at(child) else {
                continue;
            };
            if name.eq_ignore_ascii_case("Properties")
                || name.eq_ignore_ascii_case("Device Parameters")
            {
                continue;
            }
            instances.push((child, name));
        }
        if instances.is_empty() {
            let record = UsbDeviceRecord {
                device: device_name.clone(),
                instance: String::new(),
                friendly_name: first_text(&device_values, hive, "FriendlyName"),
                device_desc: first_text(&device_values, hive, "DeviceDesc"),
                service: first_text(&device_values, hive, "Service"),
                container_id: first_text(&device_values, hive, "ContainerID"),
                hardware_id: first_text(&device_values, hive, "HardwareID"),
                first_install: read_filetime_property(hive, device_cell, PROPERTY_FIRST_INSTALL),
                last_arrival: read_filetime_property(hive, device_cell, PROPERTY_LAST_ARRIVAL),
                device_last_write: device_last_write.clone(),
                instance_last_write: None,
            };
            run.record(&record)
                .from(file)
                .title(device_name.clone())
                .note(format!(r"SYSTEM\...\Enum\USBSTOR\{device_name}"))
                .emit()?;
            continue;
        }
        for (instance_cell, instance_name) in instances {
            let Ok(instance_key) = hive.key(instance_cell) else {
                continue;
            };
            let instance_values = hive.values(instance_cell).unwrap_or_default();
            let first = |name: &str| {
                first_text(&instance_values, hive, name)
                    .or_else(|| first_text(&device_values, hive, name))
            };
            let record = UsbDeviceRecord {
                device: device_name.clone(),
                instance: instance_name.clone(),
                friendly_name: first("FriendlyName"),
                device_desc: first("DeviceDesc"),
                service: first("Service"),
                container_id: first("ContainerID"),
                hardware_id: first("HardwareID"),
                first_install: read_filetime_property(
                    hive,
                    instance_cell,
                    PROPERTY_FIRST_INSTALL,
                )
                .or_else(|| read_filetime_property(hive, device_cell, PROPERTY_FIRST_INSTALL)),
                last_arrival: read_filetime_property(hive, instance_cell, PROPERTY_LAST_ARRIVAL)
                    .or_else(|| read_filetime_property(hive, device_cell, PROPERTY_LAST_ARRIVAL)),
                device_last_write: device_last_write.clone(),
                instance_last_write: filetime_timestamp(instance_key.last_write_time),
            };
            run.record(&record)
                .from(file)
                .note(format!(
                    r"SYSTEM\...\Enum\USBSTOR\{device_name}\{instance_name}"
                ))
                .emit()?;
            stats.instances += 1;
        }
    }
    Ok(Some(format!(
        "{label}: USBSTOR 设备 {} 个，实例 {} 个",
        stats.devices, stats.instances
    )))
}

fn read_filetime_property(
    hive: &Hive,
    key: u64,
    property: &str,
) -> Option<lovelycarve_plugin::Timestamp> {
    let properties = child_ci(hive, key, "Properties")?;
    let group = child_ci(hive, properties, DEVICE_PROPERTIES)?;
    let leaf = child_ci(hive, group, property)?;
    for value in hive.values(leaf).ok()? {
        if value.effective_len() < 8 {
            continue;
        }
        let data = hive.value_data(&value).ok()?;
        if data.len() < 8 {
            continue;
        }
        return filetime_timestamp(u64::from_le_bytes(data[..8].try_into().ok()?));
    }
    None
}

pub fn analyze_policy(run: &Run, file: &FileRef, hive: &Hive) -> Result<Option<String>> {
    let label = label(file);
    let Some(account) = open_first(
        hive,
        &[&["SAM", "Domains", "Account"], &["Domains", "Account"]],
    ) else {
        run.warn_file(
            file,
            "SAM_POLICY_NOT_FOUND",
            format!("{label}: 未找到 Domains\\Account 键"),
        )?;
        return Ok(None);
    };
    let values = hive.values(account).unwrap_or_default();
    let Some(value) = find_value(&values, "F") else {
        run.warn_file(
            file,
            "SAM_POLICY_NOT_FOUND",
            format!("{label}: Domains\\Account 不含 F 值"),
        )?;
        return Ok(None);
    };
    let data = match hive.value_data(value) {
        Ok(data) => data,
        Err(error) => {
            run.warn_file(
                file,
                "SAM_POLICY_READ_FAILED",
                format!("{label}: F 值读取失败（{}）", error.describe()),
            )?;
            return Ok(None);
        }
    };
    if data.len() < 0x28 {
        run.warn_file(
            file,
            "SAM_POLICY_TOO_SHORT",
            format!("{label}: F 值仅 {} 字节，不足 0x28", data.len()),
        )?;
        return Ok(None);
    }
    let raw = i64::from_le_bytes(data[0x20..0x28].try_into().unwrap_or([0; 8]));
    let (seconds, days) = if raw > 0 {
        (Some(raw / 10_000_000), Some(raw / 864_000_000_000))
    } else {
        (None, None)
    };
    let record = SamPolicyRecord {
        max_password_age_raw: raw,
        max_password_age_seconds: seconds,
        max_password_age_days: days,
        state: if raw > 0 { "set" } else { "never_or_unset" }.to_owned(),
    };
    run.record(&record)
        .from(file)
        .note("SAM\\Domains\\Account: F")
        .emit()?;
    Ok(Some(format!(
        "{label}: MaxPasswordAge raw={raw}{}",
        days.map(|days| format!("（{days} 天）"))
            .unwrap_or_else(|| "（未设置/永不过期）".to_owned())
    )))
}
