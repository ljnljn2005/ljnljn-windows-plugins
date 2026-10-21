//! FILETIME and hex helpers shared by the registry records.

use lovelycarve_plugin::Timestamp;

/// FILETIME of the Unix epoch.
pub const FILETIME_UNIX_EPOCH: u64 = 116_444_736_000_000_000;
/// Largest FILETIME that still renders inside year 9999.
pub const MAX_FILETIME: u64 = 2_650_467_743_999_999_999;

/// FILETIME (100 ns since 1601-01-01 UTC) as a UTC timestamp. Zero and
/// out-of-range values are not times; nothing is shifted to local time.
pub fn filetime_timestamp(raw: u64) -> Option<Timestamp> {
    if raw == 0 || raw > MAX_FILETIME {
        return None;
    }
    let seconds = i128::from(raw / 10_000_000) - i128::from(FILETIME_UNIX_EPOCH / 10_000_000);
    let seconds = i64::try_from(seconds).ok()?;
    let nanos = ((raw % 10_000_000) * 100) as u32;
    Some(Timestamp::from_unix_nanos(seconds, nanos))
}

/// Lowercase hex of a byte string.
pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filetime_is_utc_and_zero_is_not_a_time() {
        assert_eq!(
            filetime_timestamp(133_485_408_000_000_000).map(|value| value.as_str().to_owned()),
            Some("2024-01-01T00:00:00Z".to_owned())
        );
        assert_eq!(
            filetime_timestamp(FILETIME_UNIX_EPOCH).map(|value| value.as_str().to_owned()),
            Some("1970-01-01T00:00:00Z".to_owned())
        );
        assert!(filetime_timestamp(0).is_none());
        assert!(filetime_timestamp(MAX_FILETIME + 1).is_none());
    }

    #[test]
    fn hex_is_lowercase_and_pairs_by_byte() {
        assert_eq!(hex_lower(&[0x00, 0xAB, 0xFF]), "00abff");
    }
}
