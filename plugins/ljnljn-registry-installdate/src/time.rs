//! 时间换算：Unix 秒 → UTC ISO8601，以及 REG_SZ 里的十进制字符串解析。
//!
//! 只做 UTC 换算：不读取本机时区、不使用本机时钟、不做时区推断。
//! 原样表示（`raw_display`）单独给出，并明确标注“本地时区未知”。

/// Unix 秒可表示的上界：9999-12-31T23:59:59Z。
pub const MAX_UNIX_SECONDS: u64 = 253_402_300_799;
/// 取证上合理的下界：2000-01-01T00:00:00Z（946684800）。
///
/// 比这更早的值仍会换算（例如 0 → 1970-01-01T00:00:00Z），但会在
/// `plausibility` 里标注“明显越界/可疑”，不改变原值。
pub const PLAUSIBLE_MIN: u64 = 946_684_800;
/// 取证上合理的上界：2100-01-01T00:00:00Z（4102444800）。
pub const PLAUSIBLE_MAX: u64 = 4_102_444_800;

/// `InstallDate` 数值的可信度分级。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Plausibility {
    /// 0：Windows 常见“未写入”。
    Zero,
    /// 落在 [2000-01-01, 2100-01-01) 内。
    Plausible,
    /// 能换算成 UTC，但早于 2000 或晚于 2100（或落在 1970 之前无法表示）。
    Implausible,
    /// 超出 ISO8601 可表示范围（> 9999-12-31T23:59:59Z），无法给出 UTC 时间。
    Unrepresentable,
}

impl Plausibility {
    pub fn code(self) -> &'static str {
        match self {
            Self::Zero => "zero",
            Self::Plausible => "plausible",
            Self::Implausible => "implausible",
            Self::Unrepresentable => "unrepresentable",
        }
    }
}

/// 公历日期 → 儒略日序数（Fliegel & Van Flandern 的 64 位版本）。
#[cfg(test)]
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month = i64::from(month);
    let day = i64::from(day);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// 儒略日序数 → (年, 月, 日)。
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

/// Unix 秒（UTC）→ `YYYY-MM-DDTHH:MM:SSZ`；超出 1970..9999 返回 `None`。
pub fn unix_to_iso8601(seconds: u64) -> Option<String> {
    if seconds > MAX_UNIX_SECONDS {
        return None;
    }
    unix_to_iso8601_signed(seconds as i64)
}

/// 有符号版本（负秒返回 `None`，Unix 之前的时间不作为安装时间处理）。
pub fn unix_to_iso8601_signed(seconds: i64) -> Option<String> {
    if seconds < 0 || seconds as u64 > MAX_UNIX_SECONDS {
        return None;
    }
    let seconds = seconds as u64;
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);
    Some(format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rest / 3600,
        (rest % 3600) / 60,
        rest % 60
    ))
}

/// 公历日期 → 自 1970-01-01 起的天数（单元测试对照用）。
#[cfg(test)]
pub fn civil_days(year: i64, month: u32, day: u32) -> i64 {
    days_from_civil(year, month, day)
}

/// Unix 秒的可信度分级。
pub fn plausibility(seconds: u64) -> Plausibility {
    if seconds == 0 {
        Plausibility::Zero
    } else if seconds > MAX_UNIX_SECONDS {
        Plausibility::Unrepresentable
    } else if (PLAUSIBLE_MIN..PLAUSIBLE_MAX).contains(&seconds) {
        Plausibility::Plausible
    } else {
        Plausibility::Implausible
    }
}

/// FILETIME（100ns since 1601-01-01 UTC）→ ISO8601；0 或越界返回 `None`。
pub fn filetime_to_iso8601(raw: u64) -> Option<String> {
    const EPOCH_DELTA_100NS: u64 = 116_444_736_000_000_000;
    if raw == 0 || raw < EPOCH_DELTA_100NS {
        return None;
    }
    let seconds = (raw - EPOCH_DELTA_100NS) / 10_000_000;
    unix_to_iso8601(seconds)
}

/// REG_SZ 里的十进制字符串 → 数值。
///
/// 允许两侧空白与一个可选的 `0x`/`0X` 十六进制前缀（Windows 上 InstallDate 以
/// 字符串形式写入时是十进制，这里额外宽松地接受十六进制并在调用方标注）。
/// 空串、负号、其它字符一律 `None`（调用方保留原文并记为不支持）。
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedText {
    Decimal(u64),
    Hex(u64),
}

pub fn parse_decimal_text(text: &str) -> Option<ParsedText> {
    let trimmed = text.trim_matches(|character: char| character == '\0' || character.is_whitespace());
    if trimmed.is_empty() {
        return None;
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        if hex.is_empty() || !hex.chars().all(|character| character.is_ascii_hexdigit()) {
            return None;
        }
        return u64::from_str_radix(hex, 16).ok().map(ParsedText::Hex);
    }
    if !trimmed.chars().all(|character| character.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<u64>().ok().map(ParsedText::Decimal)
}

/// 十六进制原值展示：DWORD 为 8 位，其它按数据长度至少 8 位。
pub fn hex_raw(raw: u64, width: usize) -> String {
    format!("0x{:0width$x}", raw, width = width.max(8))
}

/// 原样表示：把文件里读到的原始值按原样回显，并显式标注“本地时区未知”。
///
/// 这里**不**做任何时区加减，只把 epoch 秒原样贴出。
pub fn raw_display(raw: u64, raw_type_label: &str) -> String {
    format!("{raw}（{raw_type_label} 原值，Unix 秒，本地时区未知）")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_unix_instants_render_correctly() {
        assert_eq!(unix_to_iso8601(0).as_deref(), Some("1970-01-01T00:00:00Z"));
        assert_eq!(
            unix_to_iso8601(1_325_750_400).as_deref(),
            Some("2012-01-05T08:00:00Z")
        );
        assert_eq!(
            unix_to_iso8601(1_620_038_668).as_deref(),
            Some("2021-05-03T10:44:28Z")
        );
        assert_eq!(
            unix_to_iso8601(MAX_UNIX_SECONDS).as_deref(),
            Some("9999-12-31T23:59:59Z")
        );
        assert_eq!(unix_to_iso8601(MAX_UNIX_SECONDS + 1), None);
        assert_eq!(unix_to_iso8601_signed(-1), None);
    }

    #[test]
    fn leap_days_and_month_boundaries_round_trip() {
        for (year, month, day) in [(1601, 1, 1), (1970, 1, 1), (2024, 2, 29), (9999, 12, 31)] {
            assert_eq!(civil_from_days(civil_days(year, month, day)), (year, month, day));
        }
        // 2024-02-29T12:34:56Z
        let seconds = civil_days(2024, 2, 29) as u64 * 86_400 + 12 * 3600 + 34 * 60 + 56;
        assert_eq!(
            unix_to_iso8601(seconds).as_deref(),
            Some("2024-02-29T12:34:56Z")
        );
    }

    #[test]
    fn plausibility_flags_zero_and_outliers() {
        assert_eq!(plausibility(0), Plausibility::Zero);
        assert_eq!(plausibility(PLAUSIBLE_MIN), Plausibility::Plausible);
        assert_eq!(plausibility(PLAUSIBLE_MAX - 1), Plausibility::Plausible);
        assert_eq!(plausibility(PLAUSIBLE_MAX), Plausibility::Implausible);
        assert_eq!(plausibility(86_400), Plausibility::Implausible);
        assert_eq!(
            plausibility(MAX_UNIX_SECONDS + 1),
            Plausibility::Unrepresentable
        );
    }

    #[test]
    fn decimal_text_parsing_accepts_whitespace_and_rejects_junk() {
        assert_eq!(parse_decimal_text("1620038668"), Some(ParsedText::Decimal(1_620_038_668)));
        assert_eq!(
            parse_decimal_text("  1620038668 \0"),
            Some(ParsedText::Decimal(1_620_038_668))
        );
        assert_eq!(parse_decimal_text("0x5F5E100"), Some(ParsedText::Hex(100_000_000)));
        assert_eq!(parse_decimal_text(""), None);
        assert_eq!(parse_decimal_text("   "), None);
        assert_eq!(parse_decimal_text("-1"), None);
        assert_eq!(parse_decimal_text("2021-05-03"), None);
        assert_eq!(parse_decimal_text("0x"), None);
        assert_eq!(parse_decimal_text("12a"), None);
        assert_eq!(parse_decimal_text("18446744073709551616"), None);
    }

    #[test]
    fn raw_display_states_local_timezone_unknown() {
        let text = raw_display(1_620_038_668, "REG_DWORD");
        assert!(text.starts_with("1620038668"));
        assert!(text.contains("本地时区未知"));
        assert_eq!(hex_raw(1_620_038_668, 8), "0x608fd40c");
        assert_eq!(hex_raw(1, 16), "0x0000000000000001");
    }

    #[test]
    fn filetime_converts_to_utc() {
        assert_eq!(
            filetime_to_iso8601(116_444_736_000_000_000).as_deref(),
            Some("1970-01-01T00:00:00Z")
        );
        assert_eq!(
            filetime_to_iso8601(133_485_408_000_000_000).as_deref(),
            Some("2024-01-01T00:00:00Z")
        );
        assert_eq!(filetime_to_iso8601(0), None);
        assert_eq!(filetime_to_iso8601(5), None);
    }
}