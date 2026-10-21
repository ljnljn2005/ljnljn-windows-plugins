//! Windows USB storage history from the SYSTEM hive (LPP v2).
//!
//! The host runs this analyzer once per identified Windows system with the
//! SYSTEM hive as its declared input. Every USBSTOR device instance becomes
//! a typed `windows.usb.device` record. The device and instance key last
//! write times, plus the first-install and last-arrival properties when the
//! hive carries them, are exposed as timestamps. Missing or malformed hives
//! are warnings, not silent empty successes.

#[allow(dead_code)]
mod regf;

#[cfg(test)]
mod testhive;
#[cfg(test)]
mod tests;

use lovelycarve_plugin::{export_plugin, Plugin, Record, Result, Run, Timestamp};

use crate::regf::{Hive, ValueNode};

/// USBSTOR device property set that carries first-install and last-arrival.
const DEVICE_PROPERTIES: &str = "83da6326-97a6-4088-9453-a1923f573b29";
/// First install time (FILETIME) under [`DEVICE_PROPERTIES`].
const PROPERTY_FIRST_INSTALL: &str = "0064";
/// Last arrival time (FILETIME) under [`DEVICE_PROPERTIES`].
const PROPERTY_LAST_ARRIVAL: &str = "0066";

/// Largest SYSTEM hive accepted by this analyzer.
const HIVE_CAP: u64 = 256 * 1024 * 1024;

#[derive(Record)]
#[record(
    id = "windows.usb.device",
    label = "USB 存储设备",
    title = "{device} / {instance}"
)]
struct UsbDevice {
    #[field(label = "设备键", key)]
    device: String,
    #[field(label = "实例键", key)]
    instance: String,
    #[field(label = "设备名称")]
    friendly_name: Option<String>,
    #[field(label = "设备描述")]
    device_desc: Option<String>,
    #[field(label = "驱动服务")]
    service: Option<String>,
    #[field(label = "容器 ID")]
    container_id: Option<String>,
    #[field(label = "硬件 ID")]
    hardware_id: Option<String>,
    #[field(label = "首次安装")]
    first_install: Option<Timestamp>,
    #[field(label = "最后接入")]
    last_arrival: Option<Timestamp>,
    #[field(label = "注册表键最后写入", timeline = "modified")]
    key_last_write: Option<Timestamp>,
}

fn usbstor(run: &Run) -> Result<()> {
    let mut devices = 0usize;
    let mut instances = 0usize;
    let mut files = 0usize;
    let mut summaries = Vec::new();

    for file in run.inputs() {
        run.check_cancelled()?;
        files += 1;
        let bytes = match file.read_all(HIVE_CAP) {
            Ok(bytes) => bytes,
            Err(error) => {
                run.warn_file(file, &error.code, error.message.clone())?;
                continue;
            }
        };
        let hive = match Hive::open(bytes) {
            Ok(hive) => hive,
            Err(error) => {
                run.warn_file(
                    file,
                    "INVALID_SYSTEM_HIVE",
                    format!("{}: {}", file.name(), error.message),
                )?;
                continue;
            }
        };
        let Some(root) = open_first(
            &hive,
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
                format!("{}: 未找到 Enum\\USBSTOR", file.name()),
            )?;
            continue;
        };
        let device_cells = hive.subkey_cells(root).unwrap_or_default();
        devices += device_cells.len();
        let mut file_instances = 0usize;
        for device_cell in device_cells {
            run.check_cancelled()?;
            let Ok(device_name) = hive.key_name_at(device_cell) else {
                continue;
            };
            let device_key = hive.key(device_cell).ok();
            let device_last_write = device_key
                .as_ref()
                .and_then(|key| filetime_timestamp(key.last_write_time));
            let device_values = hive.values(device_cell).unwrap_or_default();

            let instance_cells = hive.subkey_cells(device_cell).unwrap_or_default();
            for instance_cell in instance_cells {
                let Ok(instance_name) = hive.key_name_at(instance_cell) else {
                    continue;
                };
                if instance_name.eq_ignore_ascii_case("Properties")
                    || instance_name.eq_ignore_ascii_case("Device Parameters")
                {
                    continue;
                }
                let instance_key = match hive.key(instance_cell) {
                    Ok(key) => key,
                    Err(_) => continue,
                };
                let instance_values = hive.values(instance_cell).unwrap_or_default();

                let first_install = read_filetime_property(&hive, instance_cell, PROPERTY_FIRST_INSTALL)
                    .or_else(|| read_filetime_property(&hive, device_cell, PROPERTY_FIRST_INSTALL));
                let last_arrival = read_filetime_property(&hive, instance_cell, PROPERTY_LAST_ARRIVAL)
                    .or_else(|| read_filetime_property(&hive, device_cell, PROPERTY_LAST_ARRIVAL));

                let record = UsbDevice {
                    device: device_name.clone(),
                    instance: instance_name.clone(),
                    friendly_name: first_text(&hive, &instance_values, &device_values, "FriendlyName"),
                    device_desc: first_text(&hive, &instance_values, &device_values, "DeviceDesc"),
                    service: first_text(&hive, &instance_values, &device_values, "Service"),
                    container_id: first_text(&hive, &instance_values, &device_values, "ContainerID"),
                    hardware_id: first_text(&hive, &instance_values, &device_values, "HardwareID"),
                    first_install,
                    last_arrival,
                    key_last_write: filetime_timestamp(instance_key.last_write_time)
                        .or(device_last_write.clone()),
                };
                run.record(&record)
                    .from(file)
                    .note(format!("SYSTEM\\...\\Enum\\USBSTOR\\{device_name}\\{instance_name}"))
                    .emit()?;
                instances += 1;
                file_instances += 1;
            }
        }
        summaries.push(format!("{}: {} 个实例", file.name(), file_instances));
    }

    if files == 0 {
        run.warn("INPUT_NOT_FOUND", "未找到 Windows/System32/config/SYSTEM")?;
    }
    if instances == 0 {
        run.set_summary(format!("未发现 USBSTOR 设备实例（扫描 {files} 个 SYSTEM hive）"));
    } else {
        run.set_summary(format!(
            "USBSTOR 设备 {devices} 个，实例 {instances} 个（{}）",
            summaries.join("；")
        ));
    }
    Ok(())
}

fn open_first(hive: &Hive, paths: &[&[&str]]) -> Option<u64> {
    paths.iter().find_map(|path| hive.open_key(path).ok())
}

fn child_ci(hive: &Hive, parent: u64, name: &str) -> Option<u64> {
    hive.subkey_cells(parent).ok()?.into_iter().find(|cell| {
        hive.key_name_at(*cell)
            .map(|child| child.eq_ignore_ascii_case(name))
            .unwrap_or(false)
    })
}

fn read_filetime_property(hive: &Hive, key: u64, property: &str) -> Option<Timestamp> {
    let properties = child_ci(hive, key, "Properties")?;
    let group = child_ci(hive, properties, DEVICE_PROPERTIES)?;
    let leaf = child_ci(hive, group, property)?;
    let values = hive.values(leaf).ok()?;
    for value in values {
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

fn first_text(
    hive: &Hive,
    instance_values: &[ValueNode],
    device_values: &[ValueNode],
    name: &str,
) -> Option<String> {
    find_value(instance_values, name)
        .and_then(|value| value_text(hive, value))
        .or_else(|| find_value(device_values, name).and_then(|value| value_text(hive, value)))
}

fn find_value<'a>(values: &'a [ValueNode], name: &str) -> Option<&'a ValueNode> {
    values
        .iter()
        .find(|value| value.name.eq_ignore_ascii_case(name))
}

fn value_text(hive: &Hive, value: &ValueNode) -> Option<String> {
    let data = hive.value_data(value).ok()?;
    match value.data_type {
        1 | 2 => decode_utf16(&data),
        7 => decode_utf16_multi(&data),
        _ => None,
    }
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
    String::from_utf16(&units).ok().filter(|text| !text.is_empty())
}

fn decode_utf16_multi(raw: &[u8]) -> Option<String> {
    if raw.len() % 2 != 0 {
        return None;
    }
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let text = String::from_utf16(&units).ok()?;
    let text = text.trim_end_matches('\u{0}').replace('\u{0}', " | ");
    (!text.is_empty()).then_some(text)
}

fn filetime_timestamp(filetime: u64) -> Option<Timestamp> {
    if filetime == 0 || filetime > 2_650_467_743_999_999_999 {
        return None;
    }
    let seconds = (filetime / 10_000_000).checked_sub(11_644_473_600)?;
    let seconds = i64::try_from(seconds).ok()?;
    let nanos = ((filetime % 10_000_000) * 100) as u32;
    Some(Timestamp::from_unix_nanos(seconds, nanos.min(999_999_999)))
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.windows-usb-history")
        .record::<UsbDevice>()
        .analyzer("usbstor", usbstor)
}

export_plugin!(plugin);
