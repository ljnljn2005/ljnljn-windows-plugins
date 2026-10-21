//! 与宿主无关的提取逻辑：输入一个 [`ReadAt`] 句柄，输出 [`HiveReport`]。
//!
//! 结果由 [`crate::render`] 转成 LPP v1 结果。单元测试直接调用这里的函数、
//! 验证工具通过 SDK 句柄间接调用，两条路径都走同一份解析代码。
//!
//! 分析范围（首版，显式限定）：
//! * `Microsoft\Windows NT\CurrentVersion`（键名大小写不敏感）下的
//!   `InstallDate`（REG_DWORD 或十进制字符串 REG_SZ）；
//! * 只读辅助值 `ProductName` / `CurrentBuild` / `CurrentBuildNumber` /
//!   `CurrentVersion` / `CurrentMajorVersionNumber` /
//!   `CurrentMinorVersionNumber` / `DisplayVersion` / `ReleaseId` / `UBR` /
//!   `EditionID` / `ProductId` / `RegisteredOwner`（存在才输出）。
//!
//! 不实现：SYSTEM hive 里的安装时间相关键、安装日志交叉验证、时区推断。

use crate::regf::{
    filetime_unused_marker, Hive, HiveError, HiveValue, KeyNode, ReadAt, ValueType,
    NO_CELL, BASE_BLOCK_SIZE,
};
use crate::time::{
    filetime_to_iso8601, hex_raw, parse_decimal_text, plausibility, raw_display, unix_to_iso8601,
    ParsedText, Plausibility,
};

/// 目标键路径（相对根，`\` 分隔，大小写不敏感）。
pub const TARGET_KEY: &str = r"Microsoft\Windows NT\CurrentVersion";
/// 目标键分段。
pub const TARGET_SEGMENTS: [&str; 3] = ["Microsoft", "Windows NT", "CurrentVersion"];
/// 目标值名。
pub const TARGET_VALUE: &str = "InstallDate";

/// 只读辅助值（存在才输出），顺序即报告顺序。
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

/// hive 的来源描述（写进每条 artifact 的 `source.path` / `source.root`）。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceInfo {
    /// 单文件句柄时为文件名；卷内路径时为检材内相对路径。
    pub label: String,
    /// `file` / `volume`。
    pub kind: &'static str,
    /// 卷 id（单文件句柄时为 `None`）。
    pub root: Option<String>,
}

impl SourceInfo {
    pub fn file(name: &str) -> Self {
        Self {
            label: name.to_owned(),
            kind: "file",
            root: None,
        }
    }

    pub fn volume(root: &str, path: &str) -> Self {
        Self {
            label: path.to_owned(),
            kind: "volume",
            root: Some(root.to_owned()),
        }
    }
}

/// 报告里的告警/限制级别。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NoteLevel {
    Info,
    Warning,
}

/// 一条解析告警或限制说明。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportNote {
    /// 类别：header / key / value / time / structure / coverage。
    pub kind: &'static str,
    pub level: NoteLevel,
    pub text: String,
}

impl ReportNote {
    pub fn new(kind: &'static str, level: NoteLevel, text: impl Into<String>) -> Self {
        Self {
            kind,
            level,
            text: text.into(),
        }
    }

    pub fn warning(kind: &'static str, text: impl Into<String>) -> Self {
        Self::new(kind, NoteLevel::Warning, text)
    }

    pub fn info(kind: &'static str, text: impl Into<String>) -> Self {
        Self::new(kind, NoteLevel::Info, text)
    }
}

/// base block 自检结论（`rejected` 时其余字段为 `None`）。
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct HeaderCheck {
    pub accepted: bool,
    /// `regf` 魔数是否命中。
    pub magic_ok: bool,
    pub version: Option<String>,
    pub root_cell_offset: Option<u32>,
    pub hbins_size: Option<u32>,
    /// 存储的校验和。
    pub checksum_stored: Option<u32>,
    /// 按 0x00..0x1fb 计算出的校验和。
    pub checksum_computed: Option<u32>,
    /// 0 = 与计算值一致；1 = 存储值为占位 0（Windows 未写入）；2 = 不一致。
    pub checksum_state: &'static str,
    pub sequence: Option<(u32, u32)>,
    pub file_type: Option<u32>,
    pub file_format: Option<u32>,
    pub file_name: Option<String>,
    /// 头部 last write 原值与 UTC 形式。
    pub last_write_raw: Option<u64>,
    pub last_write_utc: Option<String>,
}

impl HeaderCheck {
    fn rejected() -> Self {
        Self {
            checksum_state: "not_checked",
            ..Self::default()
        }
    }
}

/// 目标键定位结果。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeyLookup {
    /// 目标键是否存在。
    pub exists: bool,
    /// 实际枚举到的键路径（保留原始大小写）。
    pub resolved_path: Option<String>,
    /// 第一个缺失的路径段。
    pub missing_segment: Option<String>,
    /// 目标键 cell 偏移。
    pub cell_offset: Option<u32>,
    /// 目标键 last write（FILETIME 原值与 UTC）。
    pub last_write_raw: Option<u64>,
    pub last_write_utc: Option<String>,
    /// 目标键下的值数量。
    pub value_count: Option<u32>,
    /// 目标键下的值名（按枚举顺序，最多 64 个）。
    pub value_names: Vec<String>,
}

impl KeyLookup {
    fn missing(segment: String, resolved: String) -> Self {
        Self {
            exists: false,
            resolved_path: (!resolved.is_empty()).then_some(resolved),
            missing_segment: Some(segment),
            cell_offset: None,
            last_write_raw: None,
            last_write_utc: None,
            value_count: None,
            value_names: Vec::new(),
        }
    }
}

/// `InstallDate` 的判定状态。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InstallState {
    /// 键存在、值存在、类型受支持且数值可信。
    Parsed,
    /// 键或值缺失。
    Missing,
    /// 值存在，但无法给出时间（0、越界、空串、类型不支持或读取失败）。
    Unusable,
}

impl InstallState {
    pub fn code(self) -> &'static str {
        match self {
            Self::Parsed => "parsed",
            Self::Missing => "missing",
            Self::Unusable => "unusable",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Parsed => "已解析",
            Self::Missing => "缺失",
            Self::Unusable => "不可用",
        }
    }
}

/// `InstallDate` 的解析结果。
#[derive(Clone, Debug, PartialEq)]
pub struct InstallDateValue {
    pub state: InstallState,
    /// 值是否存在（状态 `Missing` 时为 false）。
    pub present: bool,
    /// 原始类型名（REG_DWORD / REG_SZ / …）。
    pub raw_type: Option<String>,
    pub raw_type_code: Option<u32>,
    /// 原值（DWORD 数值、字符串里的数值或 QWORD；无法取数时为 None）。
    pub raw_value: Option<u64>,
    /// 原始字节的十六进制。
    pub raw_hex: Option<String>,
    /// 值名原文（若包含非 ASCII 会在属性里附加转义形式）。
    pub value_name: Option<String>,
    /// 十六进制原值字符串（0x…）。
    pub hex: Option<String>,
    /// UTC ISO8601（只有能换算时才给）。
    pub utc: Option<String>,
    /// 原样表示（永远标注“本地时区未知”）。
    pub raw_display: Option<String>,
    pub plausibility: Option<Plausibility>,
    /// 定位线索：`vk` cell 偏移与数据 cell 偏移。
    pub vk_cell: Option<u32>,
    pub data_cell: Option<u32>,
    /// `vk` 在文件里的绝对偏移（0x1000 + cell 偏移）。
    pub vk_file_offset: Option<u64>,
    pub inline: Option<bool>,
    pub big_data: Option<bool>,
    /// 字符串值里是否用到了 `0x` 十六进制写法。
    pub text_hex_notation: bool,
    /// 说明文字（为什么能/不能换算）。
    pub detail: Option<String>,
}

impl Default for InstallDateValue {
    fn default() -> Self {
        Self {
            state: InstallState::Missing,
            present: false,
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
            data_cell: None,
            vk_file_offset: None,
            inline: None,
            big_data: None,
            text_hex_notation: false,
            detail: None,
        }
    }
}

impl InstallDateValue {
    fn missing(detail: impl Into<String>) -> Self {
        Self {
            state: InstallState::Missing,
            detail: Some(detail.into()),
            ..Self::default()
        }
    }
}

/// 一个只读辅助值。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuxValue {
    pub name: String,
    pub value_type: String,
    pub text: String,
    pub vk_cell: u32,
    pub data_cell: u32,
}

/// 一次 hive 分析的完整结果（与 SDK 无关）。
#[derive(Clone, Debug, PartialEq)]
pub struct HiveReport {
    pub source: SourceInfo,
    pub file_size: u64,
    /// 头部校验失败时的错误（此时 `header.accepted == false`，不解析树）。
    pub header_error: Option<HiveError>,
    pub header: HeaderCheck,
    /// 目标键不存在（未定位）时为 `None`。
    pub key: Option<KeyLookup>,
    pub install_date: InstallDateValue,
    pub aux_values: Vec<AuxValue>,
    pub notes: Vec<ReportNote>,
    /// 一句话结论（summary）。
    pub summary: String,
}

impl HiveReport {
    /// 目标键是否存在。
    pub fn key_exists(&self) -> bool {
        self.key.as_ref().is_some_and(|key| key.exists)
    }

    /// 限制说明（写进报告的 limitations 属性）。
    pub fn limitations(&self) -> &'static [&'static str] {
        LIMITATIONS
    }
}

/// 首版明确不覆盖、也不猜测的部分。
pub const LIMITATIONS: &[&str] = &[
    "只读取 Microsoft\\Windows NT\\CurrentVersion\\InstallDate；SYSTEM hive 的安装时间相关键未解析",
    "不做安装日志（setupact.log / setupapi.dev.log 等）交叉验证",
    "不做时区推断：UTC 之外不给出任何本地时间，原样表示固定标注“本地时区未知”",
    "不做年份猜测：0、越界（早于 2000 或晚于 2100）的值只保留原值并告警",
    "不解析 .LOG1/.LOG2 事务日志：hive 若处于部分写状态，序列号/校验和能提示但不能修复",
    "只解析主 hive（file type = 0）；事务日志文件头直接拒绝",
    "REG_DWORD_BIG_ENDIAN / REG_QWORD / REG_BINARY 等类型只保留原值，不换算时间",
    "检材级分析只覆盖 Windows/System32/config/SOFTWARE 与同名 .hive 文件；其它路径下的 regf 需用文件分析器单独选择",
];

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

/// 解析一个 hive 并产出报告。头部校验失败时返回“未通过校验”的报告，不解析树。
pub fn analyze_hive<S: ReadAt>(source: S, info: SourceInfo) -> HiveReport {
    let file_size = source.size();
    let mut notes = Vec::new();
    let hive = match Hive::open(source) {
        Ok(hive) => hive,
        Err(error) => {
            let header_error = Some(error.clone());
            let header = HeaderCheck::rejected();
            notes.push(ReportNote::warning(
                "header",
                format!("regf 文件头校验失败，未解析：{error}"),
            ));
            return HiveReport {
                source: info.clone(),
                file_size,
                header_error,
                header,
                key: None,
                install_date: InstallDateValue::missing("文件头校验未通过，未解析键树"),
                aux_values: Vec::new(),
                notes,
                summary: format!(
                    "{}：regf 校验未通过（{}），未解析",
                    info.label,
                    error.kind.code()
                ),
            };
        }
    };
    let header = HeaderCheck {
        accepted: true,
        magic_ok: true,
        version: Some(hive.header().version()),
        root_cell_offset: Some(hive.header().root_cell_offset),
        hbins_size: Some(hive.header().hbins_size),
        checksum_stored: Some(hive.header().checksum),
        checksum_computed: Some(hive.header().computed_checksum),
        checksum_state: if hive.header().checksum_is_placeholder() {
            "placeholder_zero"
        } else {
            "match"
        },
        sequence: Some((hive.header().sequence1, hive.header().sequence2)),
        file_type: Some(hive.header().file_type),
        file_format: Some(hive.header().file_format),
        file_name: Some(hive.header().file_name.clone()),
        last_write_raw: Some(hive.header().last_write_raw),
        last_write_utc: filetime_to_iso8601(hive.header().last_write_raw),
    };
    if hive.header().checksum_is_placeholder() {
        notes.push(ReportNote::info(
            "header",
            "base block 校验和为 0：Windows 以 0 表示“未写入”，本插件按规范放行但无法用它验证头部完整性",
        ));
    }
    if !hive.header().sequences_consistent() {
        notes.push(ReportNote::warning(
            "header",
            format!(
                "序列号不一致（{}/{}）：hive 可能处于部分写状态，读到的是写入过程中的内容",
                hive.header().sequence1, hive.header().sequence2
            ),
        ));
    }
    if header.last_write_raw == Some(0) || header.last_write_utc.is_none() {
        notes.push(ReportNote::info(
            "header",
            "头部 last write 为 0 或不可换算（Windows 10/11 常见），未作为时间依据",
        ));
    }
    if file_size > hive.bins_end() {
        notes.push(ReportNote::info(
            "structure",
            format!(
                "文件 {file_size} 字节大于头部声明的 bins 末尾 0x{:x}（尾部可能有事务日志区或填充），以头部声明为准",
                hive.bins_end()
            ),
        ));
    }

    // ---- 目标键定位 ----
    let lookup = hive.lookup_path_verbose(&TARGET_SEGMENTS);
    let mut key_report = None;
    // 结果在下面的 match 里统一赋值；这里给出「未定位」初值即可。
    #[allow(unused_assignments)]
    let mut install_date = InstallDateValue::missing("目标键未定位");
    let mut aux_values = Vec::new();
    match lookup {
        Err(error) => {
            notes.push(ReportNote::warning(
                "key",
                format!("按路径查找 {TARGET_KEY} 失败：{error}"),
            ));
            install_date = InstallDateValue::missing(format!("键树遍历失败：{error}"));
        }
        Ok(found) => {
            for warning in &found.warnings {
                notes.push(ReportNote::warning("structure", warning.to_string()));
            }
            match found.key.clone() {
                None => {
                    let segment = found
                        .missing_segment
                        .clone()
                        .unwrap_or_else(|| "?".to_owned());
                    let resolved = found.resolved_path.clone();
                    notes.push(ReportNote::warning(
                        "key",
                        if resolved.is_empty() {
                            format!("根键下没有「{segment}」，目标键 {TARGET_KEY} 不存在")
                        } else {
                            format!(
                                "目标键 {TARGET_KEY} 不存在：在「{resolved}」下找不到「{segment}」"
                            )
                        },
                    ));
                    if let Ok(root) = hive.root_key() {
                        let names = hive.subkey_entries_tolerant(&root).0;
                        let shown = names
                            .iter()
                            .take(64)
                            .map(|(_, name)| name.clone())
                            .collect::<Vec<_>>()
                            .join("、");
                        if !shown.is_empty() {
                            notes.push(ReportNote::info(
                                "structure",
                                format!("根键「{}」下的子键：{shown}", root.name),
                            ));
                        }
                    }
                    key_report = Some(KeyLookup::missing(segment.clone(), resolved.clone()));
                    aux_values = Vec::new();
                    install_date = InstallDateValue::missing(format!(
                        "目标键 {TARGET_KEY} 不存在（缺少「{segment}」），InstallDate 无从读取"
                    ));
                }
                Some(key) => {
                    let value_names = collect_value_names(&hive, &key, &mut notes);
                    install_date = read_install_date(&hive, &key, &mut notes);
                    aux_values = read_aux_values(&hive, &key, &mut notes);
                    key_report = Some(KeyLookup {
                        exists: true,
                        resolved_path: Some(found.resolved_path.clone()),
                        missing_segment: None,
                        cell_offset: Some(key.cell_offset),
                        last_write_raw: Some(key.last_write_raw),
                        last_write_utc: filetime_to_iso8601(key.last_write_raw),
                        value_count: Some(key.value_count),
                        value_names,
                    });
                }
            }
        }
    }

    // ---- 目标值 ----
    // ---- 目标值（在定位分支里已随键存在一起读取）----

    // ---- 覆盖与限制说明（固定输出，便于报告引用）----
    notes.push(ReportNote::info(
        "coverage",
        format!(
            "本次只解析 {TARGET_KEY}（键名大小写不敏感）下的 {TARGET_VALUE} 与 {} 个只读辅助值",
            AUX_VALUES.len()
        ),
    ));
    for limitation in LIMITATIONS {
        notes.push(ReportNote::info("limitation", *limitation));
    }

    let summary = build_summary(
        &info,
        file_size,
        &header,
        key_report.as_ref(),
        &install_date,
    );
    HiveReport {
        source: info,
        file_size,
        header_error: None,
        header,
        key: key_report,
        install_date,
        aux_values,
        notes,
        summary,
    }
}

fn collect_value_names<S: ReadAt>(
    hive: &Hive<S>,
    key: &KeyNode,
    notes: &mut Vec<ReportNote>,
) -> Vec<String> {
    let offsets = match hive.value_offsets(key) {
        Ok(offsets) => offsets,
        Err(error) => {
            notes.push(ReportNote::warning(
                "value",
                format!("目标键的值列表读取失败：{error}"),
            ));
            return Vec::new();
        }
    };
    let mut names = Vec::new();
    for offset in offsets.iter().take(64) {
        match hive.read_value(*offset) {
            Ok(value) => names.push(value.name.clone()),
            Err(error) => notes.push(ReportNote::warning(
                "value",
                format!("值 @0x{offset:x} 读取失败：{error}"),
            )),
        }
    }
    names
}

/// 在目标键下找 `InstallDate`（大小写不敏感），多个同名值全部记录并取第一个。
fn read_install_date<S: ReadAt>(
    hive: &Hive<S>,
    key: &KeyNode,
    notes: &mut Vec<ReportNote>,
) -> InstallDateValue {
    let offsets = match hive.value_offsets(key) {
        Ok(offsets) => offsets,
        Err(error) => {
            return InstallDateValue::missing(format!("目标键的值列表读取失败：{error}"));
        }
    };
    let mut candidates: Vec<HiveValue> = Vec::new();
    for offset in offsets {
        match hive.read_value(offset) {
            Ok(value) => {
                if crate::regf::names_equal(&value.name, TARGET_VALUE) {
                    candidates.push(value);
                }
            }
            Err(error) => notes.push(ReportNote::warning(
                "value",
                format!("读取值 @0x{offset:x} 失败（不影响其它值）：{error}"),
            )),
        }
    }
    if candidates.is_empty() {
        notes.push(ReportNote::info(
            "value",
            format!("目标键存在，但没有名为 {TARGET_VALUE} 的值"),
        ));
        return InstallDateValue::missing(format!(
            "目标键存在，但没有名为 {TARGET_VALUE} 的值"
        ));
    }
    if candidates.len() > 1 {
        notes.push(ReportNote::warning(
            "value",
            format!(
                "目标键下有 {} 个名为 {TARGET_VALUE} 的值（大小写不同），取枚举顺序中的第一个 @0x{:x}，其余：{}",
                candidates.len(),
                candidates[0].vk_cell,
                candidates[1..]
                    .iter()
                    .map(|value| format!("@0x{:x}", value.vk_cell))
                    .collect::<Vec<_>>()
                    .join("、")
            ),
        ));
    }
    interpret_value(&candidates[0], notes)
}

/// 把一个 `InstallDate` 值解释成时间（或说明为什么不能）。
pub fn interpret_value(value: &HiveValue, notes: &mut Vec<ReportNote>) -> InstallDateValue {
    let mut out = InstallDateValue {
        state: InstallState::Unusable,
        present: true,
        raw_type: Some(value.value_type.name()),
        raw_type_code: Some(value.raw_type),
        // 十六进制原始字节：直接取解析器按声明长度读到的原始字节（不受类型解释影响）。
        raw_hex: Some(value.raw_hex.clone()),
        value_name: Some(value.name.clone()),
        vk_cell: Some(value.vk_cell),
        data_cell: (value.data_cell != NO_CELL).then_some(value.data_cell),
        vk_file_offset: Some(BASE_BLOCK_SIZE + u64::from(value.vk_cell)),
        inline: Some(value.inline),
        big_data: Some(value.big_data),
        ..InstallDateValue::default()
    };
    if value.truncated {
        notes.push(ReportNote::warning(
            "value",
            format!(
                "值 @0x{:x} 声明 {} 字节，实际只读到 {} 字节（hive 截断或数据单元被覆盖），保留已读部分",
                value.vk_cell, value.declared_len, value.raw_len
            ),
        ));
    }
    let (raw, notation_hex) = match (value.value_type, &value.data) {
        (ValueType::Dword, _) => match value.dword() {
            Some(raw) => (Some(u64::from(raw)), false),
            None => {
                out.detail = Some(format!(
                    "REG_DWORD 声明 {} 字节，不足 4 字节，无法取出 32 位原值",
                    value.raw_len
                ));
                notes.push(ReportNote::warning("value", out.detail.clone().unwrap_or_default()));
                (None, false)
            }
        },
        (ValueType::Sz, _) | (ValueType::ExpandSz, _) => {
            let text = value.text().unwrap_or("");
            match parse_decimal_text(text) {
                Some(ParsedText::Decimal(raw)) => (Some(raw), false),
                Some(ParsedText::Hex(raw)) => {
                    notes.push(ReportNote::info(
                        "value",
                        format!(
                            "字符串值采用 0x 十六进制写法「{}」，按十六进制解释为 {raw}",
                            text.trim_end_matches('\0').trim()
                        ),
                    ));
                    (Some(raw), true)
                }
                None => {
                    out.detail = Some(format!(
                        "字符串「{}」不是十进制数字，保留原文不换算",
                        text.trim_end_matches('\0').trim()
                    ));
                    notes.push(ReportNote::warning("value", out.detail.clone().unwrap_or_default()));
                    (None, false)
                }
            }
        }
        (other, _) => {
            out.detail = Some(format!(
                "不支持的值类型 {}：只保留原始字节，不换算时间",
                other.name()
            ));
            notes.push(ReportNote::warning("value", out.detail.clone().unwrap_or_default()));
            (None, false)
        }
    };
    out.text_hex_notation = notation_hex;
    let Some(raw) = raw else {
        out.raw_display = None;
        return out;
    };
    out.raw_value = Some(raw);
    out.hex = Some(hex_raw(raw, if value.raw_type == 4 { 8 } else { 16 }));
    let label = value.value_type.name();
    out.raw_display = Some(raw_display(raw, &label));
    let level = plausibility(raw);
    out.plausibility = Some(level);
    match (level, unix_to_iso8601(raw)) {
        (Plausibility::Unrepresentable, _) => {
            out.state = InstallState::Unusable;
            out.detail = Some(format!(
                "{raw} 超出 ISO8601 可表示范围（最大 {} = 9999-12-31T23:59:59Z），只保留原值",
                crate::time::MAX_UNIX_SECONDS
            ));
            notes.push(ReportNote::warning("time", out.detail.clone().unwrap_or_default()));
        }
        (Plausibility::Zero, _) => {
            out.state = InstallState::Unusable;
            out.utc = None;
            out.detail = Some(
                "原值为 0：Windows 常见“未写入”，按约定不换算出安装时间（0 秒对应 1970-01-01 只会误导）"
                    .to_owned(),
            );
            notes.push(ReportNote::warning("time", out.detail.clone().unwrap_or_default()));
        }
        (grading, utc) => {
            out.utc = utc;
            if grading == Plausibility::Implausible {
                out.state = InstallState::Unusable;
                out.detail = Some(format!(
                    "原值 {raw} 换算为 {}，但不在 2000-01-01 ~ 2100-01-01 的合理安装区间，判为可疑（保留原值，不猜测真实年份）",
                    out.utc.clone().unwrap_or_default()
                ));
                notes.push(ReportNote::warning("time", out.detail.clone().unwrap_or_default()));
            } else {
                out.state = InstallState::Parsed;
                out.detail = Some(format!(
                    "按 Unix 秒解释：{raw} → {}（UTC）",
                    out.utc.clone().unwrap_or_default()
                ));
            }
        }
    }
    out
}

/// 按名字扫描目标键下的值列表，收集 [`AUX_VALUES`] 里命中的只读辅助值。
///
/// 真实 SOFTWARE hive 的 `CurrentVersion` 有上百个值，同一个辅助值也可能出现在
/// 不同位置，所以这里只按名字（大小写不敏感）匹配，出现多次时取第一个并记说明。
fn read_aux_values<S: ReadAt>(
    hive: &Hive<S>,
    key: &KeyNode,
    notes: &mut Vec<ReportNote>,
) -> Vec<AuxValue> {
    let offsets = match hive.value_offsets(key) {
        Ok(offsets) => offsets,
        Err(_) => return Vec::new(),
    };
    let mut values = Vec::new();
    let mut failures = 0_usize;
    for offset in offsets {
        let value = match hive.read_value(offset) {
            Ok(value) => value,
            Err(error) => {
                failures += 1;
                if failures <= 3 {
                    notes.push(ReportNote::warning(
                        "value",
                        format!("读取值 @0x{offset:x} 失败（继续扫描）：{error}"),
                    ));
                }
                continue;
            }
        };
        if crate::regf::names_equal(&value.name, TARGET_VALUE) {
            continue;
        }
        let Some(wanted) = AUX_VALUES
            .iter()
            .find(|name| crate::regf::names_equal(name, &value.name))
        else {
            continue;
        };
        if values
            .iter()
            .any(|existing: &AuxValue| existing.name.eq_ignore_ascii_case(wanted))
        {
            notes.push(ReportNote::info(
                "value",
                format!("辅助值 {wanted} 出现多次，只取第一个（@0x{:x}）", value.vk_cell),
            ));
            continue;
        }
        let text = match &value.data {
            crate::regf::ValueData::Text(text) => text.trim_end_matches('\0').to_owned(),
            other => other.display(),
        };
        values.push(AuxValue {
            name: (*wanted).to_owned(),
            value_type: value.value_type.name(),
            text,
            vk_cell: value.vk_cell,
            data_cell: value.data_cell,
        });
    }
    if failures > 3 {
        notes.push(ReportNote::warning(
            "value",
            format!("另有 {} 个值读取失败（说明已省略）", failures - 3),
        ));
    }
    values
}

fn build_summary(
    info: &SourceInfo,
    file_size: u64,
    header: &HeaderCheck,
    key: Option<&KeyLookup>,
    install_date: &InstallDateValue,
) -> String {
    let head = format!(
        "{}（{file_size} 字节，regf {}{}）",
        info.label,
        header.version.clone().unwrap_or_else(|| "?".to_owned()),
        if header.accepted { "，校验通过" } else { "，校验未通过" }
    );
    let key_state = match key {
        Some(key) if key.exists => "目标键存在",
        Some(_) => "目标键缺失",
        None => "目标键未定位",
    };
    let date = match install_date.state {
        InstallState::Parsed => format!(
            "InstallDate {} → {}",
            install_date.raw_value.unwrap_or_default(),
            install_date.utc.clone().unwrap_or_default()
        ),
        InstallState::Missing => "InstallDate 缺失".to_owned(),
        InstallState::Unusable => format!(
            "InstallDate 原值 {} 不可用（{}）",
            install_date
                .raw_value
                .map(|raw| raw.to_string())
                .or_else(|| install_date.detail.clone())
                .unwrap_or_else(|| "?".to_owned()),
            install_date
                .plausibility
                .map(|grade| grade.code())
                .unwrap_or("unsupported")
        ),
    };
    format!("{head}；{key_state}；{date}")
}

/// 供报告使用的 `filetime` 辅助（避免未使用的 import 警告）。
#[allow(dead_code)]
pub(crate) fn header_time_text(raw: Option<u64>) -> String {
    match raw {
        Some(raw) => match filetime_to_iso8601(raw) {
            Some(text) => text,
            None => filetime_unused_marker(raw),
        },
        None => "(未读取)".to_owned(),
    }
}
