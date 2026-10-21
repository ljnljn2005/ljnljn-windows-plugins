//! Windows registry `InstallDate` from a regf hive (LPP v2).
//!
//! Three analyzers share one engine: a system run over the declared
//! `Windows/System32/config/SOFTWARE` input, an evidence run that resolves
//! the same input on every volume, and a file run over a hive the examiner
//! selected. The hive tree is read by the same bounds-checked regf parser
//! used by the registry/USB analyzers; the base block is inspected first so
//! a rejected file is reported with a specific reason instead of a silent
//! empty success.
//!
//! Results are typed records: the base block, the target key lookup, the
//! `InstallDate` value (raw type, raw bytes, UTC when representable, and an
//! explicit plausibility grade), auxiliary `CurrentVersion` values, and the
//! fixed coverage limitations. `InstallDate` is Unix seconds and is only
//! ever rendered as UTC; no local time zone is inferred.

mod header;
#[allow(dead_code)]
mod regf;
#[cfg(test)]
mod testhive;
#[cfg(test)]
mod tests;
mod time;

use lovelycarve_plugin::{export_plugin, Plugin, Record, Result, Run, Timestamp};

use crate::header::{Header, HeaderError};
use crate::regf::{Hive, RegfError, ValueNode};
use crate::time::{
    filetime_timestamp, hex_bytes, hex_raw, parse_numeric_text, plausibility, raw_display,
    unix_timestamp, value_type_name, ParsedText, Plausibility,
};

/// Key that carries `InstallDate` (matched case-insensitively).
pub const TARGET_KEY: &str = r"Microsoft\Windows NT\CurrentVersion";
const TARGET_SEGMENTS: [&str; 3] = ["Microsoft", "Windows NT", "CurrentVersion"];
/// Value that carries the install time (Unix seconds).
pub const TARGET_VALUE: &str = "InstallDate";
/// Read-only auxiliary values, emitted only when present.
pub const AUX_VALUES: [&str; 12] = [
    "ProductName",
    "CurrentBuild",
    "CurrentBuildNumber",
    "CurrentVersion",
    "CurrentMajorVersionNumber",
    "CurrentMinorVersionNumber",
    "DisplayVersion",
    "ReleaseId",
    "UBR",
    "EditionID",
    "ProductId",
    "RegisteredOwner",
];

/// Explicitly documented, non-guessed boundaries of this analyzer.
pub const LIMITATIONS: [&str; 8] = [
    "只读取 Microsoft\\Windows NT\\CurrentVersion\\InstallDate；SYSTEM hive 的安装相关键未解析",
    "不做安装日志（setupact.log / setupapi.dev.log 等）交叉验证",
    "不做时区推断：UTC 之外不给出任何本地时间，原样表示固定标注“本地时区未知”",
    "不做年份猜测：0、越界（早于 2000 或晚于 2100）的值只保留原值并标注",
    "不解析 .LOG1/.LOG2 事务日志：序列号/校验和能提示部分写但不能修复",
    "只解析主 hive（file type = 0）；事务日志文件头直接拒绝",
    "REG_DWORD_BIG_ENDIAN / REG_QWORD / REG_BINARY 等类型只保留原始字节，不换算时间",
    "检材/系统作用域只匹配 Windows/System32/config/SOFTWARE；其它路径的 regf 需用文件作用域单独选择",
];

/// Largest hive read into memory.
const HIVE_CAP: u64 = 1024 * 1024 * 1024;
/// Values listed for one key (the installer keys have hundreds).
const MAX_VALUE_NAMES: usize = 256;

#[derive(Record)]
#[record(
    id = "windows.installdate.hive",
    label = "InstallDate hive 校验",
    title = "{file_name}"
)]
struct HiveRecord {
    #[field(label = "来源路径", key, kind = "path")]
    source_path: String,
    #[field(label = "文件名")]
    file_name: String,
    #[field(label = "文件大小", kind = "size")]
    file_size: u64,
    #[field(label = "regf 版本")]
    version: Option<String>,
    #[field(label = "regf 校验")]
    regf_valid: bool,
    #[field(label = "魔数通过")]
    magic_ok: bool,
    #[field(label = "根键偏移")]
    root_cell_offset: Option<i64>,
    #[field(label = "hbin 区域长度", kind = "size")]
    hbins_size: Option<u64>,
    #[field(label = "校验和")]
    checksum: Option<String>,
    #[field(
        label = "校验和状态",
        kind = "enum",
        choices = "match=一致,mismatch=不一致,placeholder_zero=占位 0,not_checked=未检查"
    )]
    checksum_state: String,
    #[field(label = "序列号")]
    sequence: Option<String>,
    #[field(label = "文件类型")]
    file_type: Option<i64>,
    #[field(label = "文件格式")]
    file_format: Option<i64>,
    #[field(label = "头部最后写入", timeline = "modified")]
    header_last_write: Option<Timestamp>,
    #[field(label = "错误码")]
    error_code: Option<String>,
    #[field(label = "错误说明")]
    error_detail: Option<String>,
}

#[derive(Record)]
#[record(
    id = "windows.installdate.key",
    label = "InstallDate 目标键",
    title = "{target}"
)]
struct KeyRecord {
    #[field(label = "目标键", key)]
    target: String,
    #[field(label = "键存在")]
    exists: bool,
    #[field(label = "实际路径")]
    resolved_path: Option<String>,
    #[field(label = "缺失路径段")]
    missing_segment: Option<String>,
    #[field(label = "键 cell 偏移")]
    cell_offset: Option<i64>,
    #[field(label = "键文件偏移")]
    file_offset: Option<i64>,
    #[field(label = "键最后写入", timeline = "modified")]
    last_write: Option<Timestamp>,
    #[field(label = "值数量")]
    value_count: Option<i64>,
    #[field(label = "值名")]
    value_names: Vec<String>,
}

#[derive(Record)]
#[record(
    id = "windows.installdate.value",
    label = "InstallDate 值",
    title = "{hive}"
)]
struct ValueRecord {
    #[field(label = "来源路径", key)]
    hive: String,
    #[field(
        label = "状态",
        kind = "enum",
        choices = "parsed=已解析,missing=缺失,unusable=不可用"
    )]
    state: String,
    #[field(label = "原值类型")]
    raw_type: Option<String>,
    #[field(label = "原值类型代码")]
    raw_type_code: Option<i64>,
    #[field(label = "原值")]
    raw_value: Option<i64>,
    #[field(label = "原始字节")]
    raw_hex: Option<String>,
    #[field(label = "值名")]
    value_name: Option<String>,
    #[field(label = "十六进制原值")]
    hex: Option<String>,
    #[field(label = "UTC 时间", timeline = "created")]
    utc: Option<Timestamp>,
    #[field(label = "原样表示")]
    raw_display: Option<String>,
    #[field(
        label = "可信度",
        kind = "enum",
        choices = "zero=0,plausible=合理,implausible=可疑,unrepresentable=超出可表示范围,unsupported=类型不支持"
    )]
    plausibility: Option<String>,
    #[field(label = "值节点 cell 偏移")]
    vk_cell: Option<i64>,
    #[field(label = "值节点文件偏移")]
    vk_file_offset: Option<i64>,
    #[field(label = "数据 cell 偏移")]
    data_cell: Option<i64>,
    #[field(label = "数据内联")]
    inline: Option<bool>,
    #[field(label = "大值分段")]
    big_data: Option<bool>,
    #[field(label = "字符串十六进制写法")]
    text_hex_notation: bool,
    #[field(label = "判定说明")]
    detail: Option<String>,
}

#[derive(Record)]
#[record(
    id = "windows.installdate.aux",
    label = "CurrentVersion 辅助值",
    title = "{name}"
)]
struct AuxRecord {
    #[field(label = "来源路径", key)]
    hive: String,
    #[field(label = "值名", key)]
    name: String,
    #[field(label = "值类型")]
    value_type: String,
    #[field(label = "值")]
    value: String,
    #[field(label = "值节点 cell 偏移")]
    vk_cell: i64,
}

#[derive(Record)]
#[record(
    id = "windows.installdate.limitation",
    label = "解析范围与限制",
    title = "{subject}"
)]
struct LimitationRecord {
    #[field(label = "主题", key)]
    subject: String,
    #[field(label = "条目")]
    items: Vec<String>,
}

#[derive(Default)]
struct Counts {
    hives: usize,
    accepted: usize,
    parsed: usize,
    missing: usize,
    unusable: usize,
}

fn install_date(run: &Run) -> Result<()> {
    let inputs = run.inputs();
    if inputs.is_empty() {
        run.warn(
            "INPUT_NOT_FOUND",
            "未找到声明输入的 regf hive（system/evidence 作用域按清单 inputs 解析；files 作用域需要选中文件）",
        )?;
        run.set_summary("未找到可分析的 SOFTWARE hive");
        return Ok(());
    }

    let mut counts = Counts::default();
    let mut details: Vec<String> = Vec::new();
    for file in inputs {
        run.check_cancelled()?;
        counts.hives += 1;
        let label = file.root_path().unwrap_or_else(|| file.name()).to_owned();
        let bytes = match file.read_all(HIVE_CAP) {
            Ok(bytes) => bytes,
            Err(error) => {
                emit_unreadable(run, file, &label, &mut counts)?;
                run.warn_file(file, &error.code, error.message.clone())?;
                details.push(format!("{label}: 读取失败（{}）", error.message));
                continue;
            }
        };

        let inspected = header::inspect(&bytes);
        let tree = Hive::open(bytes);
        match (inspected, tree) {
            (Err(header_error), _) => {
                emit_header_record(run, file, &label, bytes_len_hint(file), None, Some(&header_error))?;
                run.warn_file(
                    file,
                    header_error.code,
                    format!("{label}: {}", header_error.detail),
                )?;
                details.push(format!("{label}: {}", header_error.detail));
            }
            (Ok(header), Err(tree_error)) => {
                emit_header_record(
                    run,
                    file,
                    &label,
                    bytes_len_hint(file),
                    Some((&header, false)),
                    Some(&tree_error_record(&tree_error)),
                )?;
                run.warn_file(
                    file,
                    "INVALID_HIVE_TREE",
                    format!("{label}: hbin/键树校验失败（{}）", tree_error.describe()),
                )?;
                details.push(format!("{label}: 键树校验失败（{}）", tree_error.describe()));
            }
            (Ok(header), Ok(hive)) => {
                counts.accepted += 1;
                emit_header_record(run, file, &label, bytes_len_hint(file), Some((&header, true)), None)?;
                if header.checksum_state() == "mismatch" {
                    run.warn_file(
                        file,
                        "HEADER_CHECKSUM_MISMATCH",
                        format!(
                            "{label}: base block 校验和不一致（{}），仍按结构解析",
                            header.checksum_text()
                        ),
                    )?;
                }
                if !header.sequences_consistent() {
                    run.warn_file(
                        file,
                        "HEADER_SEQUENCE_MISMATCH",
                        format!(
                            "{label}: base block 序列号不一致（{}/{}），hive 可能处于部分写状态",
                            header.sequence.0, header.sequence.1
                        ),
                    )?;
                }
                analyze_tree(run, file, &label, &hive, &mut counts, &mut details)?;
            }
        }
    }

    if counts.accepted == 0 {
        run.warn(
            "NO_USABLE_HIVE",
            format!(
                "{} 个输入中没有一个可作为主 hive 解析：{}",
                counts.hives,
                details.join("；")
            ),
        )?;
    }

    run.emit(&LimitationRecord {
        subject: "coverage".to_owned(),
        items: LIMITATIONS.iter().map(|text| (*text).to_owned()).collect(),
    })?;
    run.set_summary(format!(
        "SOFTWARE hive {} 个（可用 {}）；InstallDate 已解析 {}，缺失 {}，不可用 {}",
        counts.hives, counts.accepted, counts.parsed, counts.missing, counts.unusable
    ));
    Ok(())
}

fn bytes_len_hint(file: &lovelycarve_plugin::FileRef) -> u64 {
    file.size()
}

fn emit_unreadable(
    run: &Run,
    file: &lovelycarve_plugin::FileRef,
    label: &str,
    counts: &mut Counts,
) -> Result<()> {
    let source_path = label.to_owned();
    run.record(&HiveRecord {
        source_path,
        file_name: file.name().to_owned(),
        file_size: file.size(),
        version: None,
        regf_valid: false,
        magic_ok: false,
        root_cell_offset: None,
        hbins_size: None,
        checksum: None,
        checksum_state: "not_checked".to_owned(),
        sequence: None,
        file_type: None,
        file_format: None,
        header_last_write: None,
        error_code: Some("READ_FAILED".to_owned()),
        error_detail: Some("hive 读取失败，未解析".to_owned()),
    })
    .from(file)
    .emit()?;
    counts.unusable += 1;
    Ok(())
}

fn emit_header_record(
    run: &Run,
    file: &lovelycarve_plugin::FileRef,
    label: &str,
    _size: u64,
    header: Option<(&Header, bool)>,
    error: Option<&HeaderError>,
) -> Result<()> {
    let source_path = label.to_owned();
    let record = match header {
        Some((header, valid)) => HiveRecord {
            source_path,
            file_name: header.file_name.clone(),
            file_size: file.size(),
            version: Some(header.version()),
            regf_valid: valid,
            magic_ok: true,
            root_cell_offset: Some(i64::from(header.root_cell_offset)),
            hbins_size: Some(u64::from(header.hbins_size)),
            checksum: Some(header.checksum_text()),
            checksum_state: header.checksum_state().to_owned(),
            sequence: Some(format!("{}/{}", header.sequence.0, header.sequence.1)),
            file_type: Some(i64::from(header.file_type)),
            file_format: Some(i64::from(header.file_format)),
            header_last_write: header.last_write.clone(),
            error_code: error.map(|error| error.code.to_owned()),
            error_detail: error.map(|error| error.detail.clone()),
        },
        None => HiveRecord {
            source_path,
            file_name: file.name().to_owned(),
            file_size: file.size(),
            version: None,
            regf_valid: false,
            magic_ok: false,
            root_cell_offset: None,
            hbins_size: None,
            checksum: None,
            checksum_state: "not_checked".to_owned(),
            sequence: None,
            file_type: None,
            file_format: None,
            header_last_write: None,
            error_code: error.map(|error| error.code.to_owned()),
            error_detail: error.map(|error| error.detail.clone()),
        },
    };
    run.record(&record).from(file).emit()
}

fn tree_error_record(error: &RegfError) -> HeaderError {
    HeaderError {
        code: "INVALID_HIVE_TREE",
        detail: format!("stage={}: {}", error.stage.as_str(), error.message),
    }
}

fn analyze_tree(
    run: &Run,
    file: &lovelycarve_plugin::FileRef,
    label: &str,
    hive: &Hive,
    counts: &mut Counts,
    details: &mut Vec<String>,
) -> Result<()> {
    let lookup = match open_key_ci(hive, &TARGET_SEGMENTS) {
        Ok(lookup) => lookup,
        Err(error) => {
            run.warn_file(
                file,
                "KEY_LOOKUP_FAILED",
                format!("{label}: 按路径查找 {TARGET_KEY} 失败（{}）", error.describe()),
            )?;
            details.push(format!("{label}: 键树遍历失败"));
            emit_key_record(run, file, None, None)?;
            emit_value_record(run, file, label, ValueRecord::missing("键树遍历失败"))?;
            counts.missing += 1;
            return Ok(());
        }
    };

    let Some(cell) = lookup.cell else {
        let missing = lookup.missing.clone().unwrap_or_else(|| "?".to_owned());
        let resolved = lookup.resolved.join("\\");
        run.warn_file(
            file,
            "TARGET_KEY_MISSING",
            if resolved.is_empty() {
                format!("{label}: 根键下没有「{missing}」，目标键 {TARGET_KEY} 不存在")
            } else {
                format!("{label}: 目标键 {TARGET_KEY} 不存在：在「{resolved}」下找不到「{missing}」")
            },
        )?;
        details.push(format!("{label}: 目标键缺失"));
        emit_key_record(run, file, Some(lookup), None)?;
        emit_value_record(
            run,
            file,
            label,
            ValueRecord::missing(format!("目标键 {TARGET_KEY} 不存在")),
        )?;
        counts.missing += 1;
        return Ok(());
    };

    let key = match hive.key(cell) {
        Ok(key) => key,
        Err(error) => {
            run.warn_file(
                file,
                "KEY_READ_FAILED",
                format!("{label}: 目标键读取失败（{}）", error.describe()),
            )?;
            emit_key_record(run, file, Some(lookup), None)?;
            emit_value_record(run, file, label, ValueRecord::missing("目标键读取失败"))?;
            counts.missing += 1;
            return Ok(());
        }
    };
    let values = hive.values(cell).unwrap_or_default();
    emit_key_record(run, file, Some(lookup), Some((&key, &values)))?;

    let mut install_date = None;
    let mut duplicates = Vec::new();
    for value in &values {
        if value.name.eq_ignore_ascii_case(TARGET_VALUE) {
            if install_date.is_none() {
                install_date = Some(value);
            } else {
                duplicates.push(value.cell);
            }
        }
    }
    if !duplicates.is_empty() {
        run.warn_file(
            file,
            "INSTALL_DATE_MULTIPLE",
            format!(
                "{label}: 目标键下有 {} 个名为 {TARGET_VALUE} 的值（大小写不同），取第一个 @0x{:x}，其余：{}",
                duplicates.len() + 1,
                install_date.map(|value| value.cell).unwrap_or(0),
                duplicates
                    .iter()
                    .map(|cell| format!("@0x{cell:x}"))
                    .collect::<Vec<_>>()
                    .join("、")
            ),
        )?;
    }

    match install_date {
        None => {
            run.warn_file(
                file,
                "INSTALL_DATE_MISSING",
                format!("{label}: 目标键存在，但没有名为 {TARGET_VALUE} 的值"),
            )?;
            details.push(format!("{label}: InstallDate 缺失"));
            emit_value_record(
                run,
                file,
                label,
                ValueRecord::missing(format!("目标键存在，但没有名为 {TARGET_VALUE} 的值")),
            )?;
            counts.missing += 1;
        }
        Some(value) => {
            let data = match hive.value_data(value) {
                Ok(data) => data,
                Err(error) => {
                    run.warn_file(
                        file,
                        "VALUE_READ_FAILED",
                        format!("{label}: InstallDate 值读取失败（{}）", error.describe()),
                    )?;
                    emit_value_record(
                        run,
                        file,
                        label,
                        ValueRecord::unusable(
                            value,
                            None,
                            format!("值读取失败：{}", error.describe()),
                        ),
                    )?;
                    counts.unusable += 1;
                    return Ok(());
                }
            };
            let big_data = hive.value_is_big_data(value);
            let (record, note) = interpret_install_date(value, &data, big_data);
            match record.state.as_str() {
                "parsed" => counts.parsed += 1,
                "missing" => counts.missing += 1,
                _ => counts.unusable += 1,
            }
            if let Some((code, message)) = note {
                run.warn_file(file, code, format!("{label}: {message}"))?;
            }
            emit_value_record(run, file, label, record)?;
        }
    }

    emit_aux_values(run, file, label, hive, &values)?;
    Ok(())
}

fn emit_key_record(
    run: &Run,
    file: &lovelycarve_plugin::FileRef,
    lookup: Option<Lookup>,
    key: Option<(&crate::regf::KeyNode, &[ValueNode])>,
) -> Result<()> {
    let mut record = KeyRecord {
        target: TARGET_KEY.to_owned(),
        exists: false,
        resolved_path: None,
        missing_segment: None,
        cell_offset: None,
        file_offset: None,
        last_write: None,
        value_count: None,
        value_names: Vec::new(),
    };
    if let Some(lookup) = lookup {
        record.exists = lookup.cell.is_some();
        record.resolved_path = (!lookup.resolved.is_empty()).then(|| lookup.resolved.join("\\"));
        record.missing_segment = lookup.missing;
        if let Some(cell) = lookup.cell {
            record.cell_offset = Some(cell as i64);
            record.file_offset = Some((crate::regf::BASE_BLOCK_SIZE as u64 + cell) as i64);
        }
    }
    if let Some((key, values)) = key {
        record.last_write = filetime_timestamp(key.last_write_time);
        record.value_count = Some(values.len() as i64);
        record.value_names = values
            .iter()
            .take(MAX_VALUE_NAMES)
            .map(|value| value.name.clone())
            .collect();
    }
    run.record(&record).from(file).emit()
}

impl ValueRecord {
    fn blank(hive: String, state: &str) -> Self {
        Self {
            hive,
            state: state.to_owned(),
            raw_type: None,
            raw_type_code: None,
            raw_value: None,
            raw_hex: None,
            value_name: None,
            hex: None,
            utc: None,
            raw_display: None,
            plausibility: None,
            vk_cell: None,
            vk_file_offset: None,
            data_cell: None,
            inline: None,
            big_data: None,
            text_hex_notation: false,
            detail: None,
        }
    }

    fn missing(detail: impl Into<String>) -> Self {
        let mut record = Self::blank(String::new(), "missing");
        record.detail = Some(detail.into());
        record
    }

    fn unusable(value: &ValueNode, raw_value: Option<u64>, detail: String) -> Self {
        let mut record = Self::blank(String::new(), "unusable");
        record.raw_type = Some(value_type_name(value.data_type).to_owned());
        record.raw_type_code = Some(i64::from(value.data_type));
        record.raw_value = raw_value.and_then(|raw| i64::try_from(raw).ok());
        record.value_name = Some(value.name.clone());
        record.vk_cell = Some(value.cell as i64);
        record.vk_file_offset = Some((crate::regf::BASE_BLOCK_SIZE as u64 + value.cell) as i64);
        record.data_cell = value.data.map(|cell| cell as i64);
        record.inline = Some(value.is_inline());
        record.detail = Some(detail);
        record
    }
}

fn emit_value_record(
    run: &Run,
    file: &lovelycarve_plugin::FileRef,
    label: &str,
    mut record: ValueRecord,
) -> Result<()> {
    if record.hive.is_empty() {
        record.hive = label.to_owned();
    }
    run.record(&record).from(file).emit()
}

/// Interprets the `InstallDate` value. Returns the record and an optional
/// `(warning code, message)` pair for values that need an explicit note.
fn interpret_install_date(
    value: &ValueNode,
    data: &[u8],
    big_data: bool,
) -> (ValueRecord, Option<(&'static str, String)>) {
    let type_name = value_type_name(value.data_type);
    let mut record = ValueRecord {
        state: "unusable".to_owned(),
        raw_type: Some(type_name.to_owned()),
        raw_type_code: Some(i64::from(value.data_type)),
        raw_hex: (!data.is_empty()).then(|| hex_bytes(data)),
        value_name: Some(value.name.clone()),
        vk_cell: Some(value.cell as i64),
        vk_file_offset: Some((crate::regf::BASE_BLOCK_SIZE as u64 + value.cell) as i64),
        data_cell: value.data.map(|cell| cell as i64),
        inline: Some(value.is_inline()),
        big_data: Some(big_data),
        ..ValueRecord::blank(String::new(), "unusable")
    };
    let (raw, hex_notation, detail) = match value.data_type {
        4 => {
            if data.len() < 4 {
                (
                    None,
                    false,
                    Some(format!(
                        "REG_DWORD 只读到 {} 字节，不足 4 字节，无法取出原值",
                        data.len()
                    )),
                )
            } else {
                (
                    Some(u64::from(u32::from_le_bytes(
                        data[..4].try_into().unwrap_or([0; 4]),
                    ))),
                    false,
                    None,
                )
            }
        }
        1 | 2 => {
            let text = decode_utf16(data).unwrap_or_default();
            match parse_numeric_text(&text) {
                Some(ParsedText::Decimal(raw)) => (Some(raw), false, None),
                Some(ParsedText::Hex(raw)) => (Some(raw), true, None),
                None => (
                    None,
                    false,
                    Some(format!(
                        "字符串「{}」不是十进制数字，保留原文不换算",
                        text.trim_end_matches('\0').trim()
                    )),
                ),
            }
        }
        other => (
            None,
            false,
            Some(format!(
                "不支持的值类型 {type_name}（{other}）：只保留原始字节，不换算时间"
            )),
        ),
    };
    record.text_hex_notation = hex_notation;
    let Some(raw) = raw else {
        record.detail = detail;
        return (record, None);
    };
    record.raw_value = i64::try_from(raw).ok();
    record.hex = Some(hex_raw(raw, if value.data_type == 4 { 8 } else { 16 }));
    record.raw_display = Some(raw_display(raw, type_name));
    if record.raw_value.is_none() {
        record.detail = Some(format!("{raw} 超出 64 位有符号整数，原值只以十六进制保留"));
        return (record, None);
    }
    let grade = plausibility(raw);
    record.plausibility = Some(grade.code().to_owned());
    let utc = unix_timestamp(raw);
    let mut warning = None;
    match grade {
        Plausibility::Zero => {
            record.detail = Some(
                "原值为 0：Windows 常见“未写入”，不换算出安装时间（0 秒对应 1970-01-01 会误导）"
                    .to_owned(),
            );
            warning = Some((
                "INSTALL_DATE_ZERO",
                "InstallDate 原值为 0，按未写入处理，不给出时间".to_owned(),
            ));
        }
        Plausibility::Unrepresentable => {
            record.detail = Some(format!(
                "{raw} 超出 ISO 8601 可表示范围（最大 {} = 9999-12-31T23:59:59Z），只保留原值",
                time::MAX_UNIX_SECONDS
            ));
            warning = Some((
                "INSTALL_DATE_UNREPRESENTABLE",
                "InstallDate 超出可表示的年份范围，只保留原值".to_owned(),
            ));
        }
        Plausibility::Implausible => {
            record.utc = utc;
            record.detail = Some(format!(
                "原值 {raw} 换算为 {}，但不在 2000-01-01 ~ 2100-01-01 的合理安装区间，判为可疑",
                record.utc.as_ref().map(Timestamp::as_str).unwrap_or("")
            ));
            warning = Some((
                "INSTALL_DATE_IMPLAUSIBLE",
                "InstallDate 换算结果不在合理安装区间，保留原值并标注可疑".to_owned(),
            ));
        }
        Plausibility::Plausible => {
            record.utc = utc;
            record.state = "parsed".to_owned();
            record.detail = Some(format!(
                "按 Unix 秒解释：{raw} → {}（UTC）",
                record.utc.as_ref().map(Timestamp::as_str).unwrap_or("")
            ));
        }
    }
    (record, warning)
}

fn emit_aux_values(
    run: &Run,
    file: &lovelycarve_plugin::FileRef,
    label: &str,
    hive: &Hive,
    values: &[ValueNode],
) -> Result<()> {
    let mut seen: Vec<&str> = Vec::new();
    for wanted in AUX_VALUES {
        let Some(value) = values
            .iter()
            .find(|value| value.name.eq_ignore_ascii_case(wanted))
        else {
            continue;
        };
        if seen.iter().any(|name| name.eq_ignore_ascii_case(wanted)) {
            continue;
        }
        let Ok(data) = hive.value_data(value) else {
            continue;
        };
        let text = match value.data_type {
            1 | 2 => decode_utf16(&data).unwrap_or_default(),
            4 if data.len() >= 4 => u64::from(u32::from_le_bytes(
                data[..4].try_into().unwrap_or([0; 4]),
            ))
            .to_string(),
            5 if data.len() >= 4 => u64::from(u32::from_be_bytes(
                data[..4].try_into().unwrap_or([0; 4]),
            ))
            .to_string(),
            11 if data.len() >= 8 => u64::from_le_bytes(
                data[..8].try_into().unwrap_or([0; 8]),
            )
            .to_string(),
            _ => hex_bytes(&data),
        };
        seen.push(wanted);
        let record = AuxRecord {
            hive: label.to_owned(),
            name: wanted.to_owned(),
            value_type: value_type_name(value.data_type).to_owned(),
            value: text,
            vk_cell: value.cell as i64,
        };
        run.record(&record).from(file).emit()?;
    }
    Ok(())
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

#[derive(Debug)]
struct Lookup {
    cell: Option<u64>,
    resolved: Vec<String>,
    missing: Option<String>,
}

/// Case-insensitive walk from the root. Returns the matched cell plus the
/// spelling the hive actually uses, or the first missing segment.
fn open_key_ci(hive: &Hive, segments: &[&str]) -> std::result::Result<Lookup, RegfError> {
    let mut current = hive.root_cell();
    let mut resolved = Vec::new();
    for segment in segments {
        let mut found = None;
        for subkey in hive.subkey_cells(current)? {
            if let Ok(name) = hive.key_name_at(subkey) {
                if name.eq_ignore_ascii_case(segment) {
                    found = Some((subkey, name));
                    break;
                }
            }
        }
        match found {
            Some((cell, name)) => {
                resolved.push(name);
                current = cell;
            }
            None => {
                return Ok(Lookup {
                    cell: None,
                    resolved,
                    missing: Some((*segment).to_owned()),
                })
            }
        }
    }
    Ok(Lookup {
        cell: Some(current),
        resolved,
        missing: None,
    })
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.registry-installdate")
        .record::<HiveRecord>()
        .record::<KeyRecord>()
        .record::<ValueRecord>()
        .record::<AuxRecord>()
        .record::<LimitationRecord>()
        .analyzer("installdate", install_date)
        .analyzer("installdate_evidence", install_date)
        .analyzer("installdate_file", install_date)
}

export_plugin!(plugin);
