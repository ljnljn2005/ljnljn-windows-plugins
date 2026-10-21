//! Time and raw-value helpers for the InstallDate analyzer.
//!
//! Only UTC is derived: Unix seconds for `InstallDate` and FILETIME
//! (100 ns since 1601-01-01 UTC) for registry key/header times. A value is
//! never shifted into a local time zone; the raw display text says so.

use lovelycarve_plugin::Timestamp;

/// Largest Unix second ISO 8601 can express with a four-digit year
/// (`9999-12-31T23:59:59Z`).
pub const MAX_UNIX_SECONDS: u64 = 253_402_300_799;
/// Lower bound of the plausible install window (`2000-01-01T00:00:00Z`).
pub const PLAUSIBLE_MIN: u64 = 946_684_800;
/// Exclusive upper bound of the plausible install window (`2100-01-01T00:00:00Z`).
pub const PLAUSIBLE_MAX: u64 = 4_102_444_800;
/// FILETIME of the Unix epoch.
pub const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
/// Largest FILETIME that still renders as `9999-12-31T23:59:59.9999999Z`.
pub const MAX_FILETIME: u64 = 2_650_467_743_999_999_999;

/// How a numeric `InstallDate` relates to the plausible install window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Plausibility {
    Zero,
    Plausible,
    Implausible,
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

/// Unix seconds as UTC, or `None` when ISO 8601 cannot express the year.
pub fn unix_timestamp(seconds: u64) -> Option<Timestamp> {
    (seconds <= MAX_UNIX_SECONDS).then(|| Timestamp::from_unix(seconds as i64))
}

/// FILETIME as UTC. Zero and values beyond year 9999 are not times.
pub fn filetime_timestamp(raw: u64) -> Option<Timestamp> {
    if raw == 0 || raw > MAX_FILETIME {
        return None;
    }
    let seconds = i128::from(raw / 10_000_000) - i128::from(FILETIME_UNIX_EPOCH / 10_000_000);
    let seconds = i64::try_from(seconds).ok()?;
    let nanos = ((raw % 10_000_000) * 100) as u32;
    Some(Timestamp::from_unix_nanos(seconds, nanos))
}

/// A numeric text value read from `REG_SZ` / `REG_EXPAND_SZ`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParsedText {
    Decimal(u64),
    Hex(u64),
}

/// Parses a decimal or `0x`-prefixed hexadecimal string, tolerating
/// surrounding whitespace and NULs. Negative and non-numeric text is
/// rejected; the caller keeps the raw text and reports it.
pub fn parse_numeric_text(text: &str) -> Option<ParsedText> {
    let trimmed = text.trim_matches(|character: char| character == '\0' || character.is_whitespace());
    if trimmed.is_empty() {
        return None;
    }
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
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

/// Lowercase, space-separated hex of raw value bytes (`60 8f d4 0c`).
pub fn hex_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 3);
    for (index, byte) in bytes.iter().enumerate() {
        if index > 0 {
            out.push(' ');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// `0x…` rendering of a numeric value, at least eight digits.
pub fn hex_raw(raw: u64, width: usize) -> String {
    format!("0x{:0width$x}", raw, width = width.max(8))
}

/// The value exactly as stored, plus the unknown-zone disclaimer.
pub fn raw_display(raw: u64, type_label: &str) -> String {
    format!("{raw}（{type_label} 原值，Unix 秒，本地时区未知）")
}

/// Registry value type names (winnt.h).
pub fn value_type_name(code: u32) -> &'static str {
    match code {
        0 => "REG_NONE",
        1 => "REG_SZ",
        2 => "REG_EXPAND_SZ",
        3 => "REG_BINARY",
        4 => "REG_DWORD",
        5 => "REG_DWORD_BIG_ENDIAN",
        6 => "REG_LINK",
        7 => "REG_MULTI_SZ",
        8 => "REG_RESOURCE_LIST",
        9 => "REG_FULL_RESOURCE_DESCRIPTOR",
        10 => "REG_RESOURCE_REQUIREMENTS_LIST",
        11 => "REG_QWORD",
        _ => "REG_UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_seconds_render_as_utc_and_out_of_range_is_none() {
        assert_eq!(
            unix_timestamp(1_620_038_668).map(|value| value.as_str().to_owned()),
            Some("2021-05-03T10:44:28Z".to_owned())
        );
        assert_eq!(
            unix_timestamp(MAX_UNIX_SECONDS).map(|value| value.as_str().to_owned()),
            Some("9999-12-31T23:59:59Z".to_owned())
        );
        assert!(unix_timestamp(MAX_UNIX_SECONDS + 1).is_none());
    }

    #[test]
    fn filetime_converts_to_utc_and_zero_is_not_a_time() {
        assert_eq!(
            filetime_timestamp(133_485_408_000_000_000).map(|value| value.as_str().to_owned()),
            Some("2024-01-01T00:00:00Z".to_owned())
        );
        assert!(filetime_timestamp(0).is_none());
        assert!(filetime_timestamp(MAX_FILETIME + 1).is_none());
    }

    #[test]
    fn plausibility_grades_zero_and_outliers() {
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
    fn numeric_text_accepts_decimal_and_hex_only() {
        assert_eq!(
            parse_numeric_text(" 1620038668\0"),
            Some(ParsedText::Decimal(1_620_038_668))
        );
        assert_eq!(
            parse_numeric_text("0x608fd40c"),
            Some(ParsedText::Hex(1_620_038_668))
        );
        assert_eq!(parse_numeric_text(""), None);
        assert_eq!(parse_numeric_text("-1"), None);
        assert_eq!(parse_numeric_text("2021-05-03"), None);
    }

    #[test]
    fn raw_renderings_keep_the_unknown_zone_disclaimer() {
        assert_eq!(hex_bytes(&[0x60, 0x8f, 0xd4, 0x0c]), "60 8f d4 0c");
        assert_eq!(hex_raw(1_620_038_668, 8), "0x608fd40c");
        let text = raw_display(1_620_038_668, "REG_DWORD");
        assert!(text.starts_with("1620038668"));
        assert!(text.contains("本地时区未知"));
        assert_eq!(value_type_name(4), "REG_DWORD");
    }
}
