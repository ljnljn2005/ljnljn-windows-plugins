//! Strict parser for logical Windows Vista+ recycle-bin $I metadata files.
//! No host IO, original-path resolution, or content execution occurs here.

use std::fmt;

pub const V1_BYTES: usize = 544;
pub const MAX_PATH_UNITS: usize = 32768;
pub const MAX_RECORD_BYTES: usize = 28 + MAX_PATH_UNITS * 2;
const EPOCH_FILETIME: u64 = 116_444_736_000_000_000;
const MAX_FILETIME: u64 = 2_650_467_743_999_999_999;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub version: u64,
    pub original_size: u64,
    pub deleted_filetime: u64,
    pub deleted_unix_nanos: i128,
    pub original_path: String,
}

impl Record {
    pub fn original_name(&self) -> &str {
        self.original_path.rsplit(['\\', '/']).next().unwrap_or("")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub &'static str);

impl fmt::Display for ParseError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

fn u64_at(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        data[offset..offset + 8]
            .try_into()
            .expect("validated header"),
    )
}

pub fn parse_i(data: &[u8]) -> Result<Record, ParseError> {
    if !(24..=MAX_RECORD_BYTES).contains(&data.len()) {
        return Err(ParseError(
            "$I metadata length is outside the supported bound",
        ));
    }
    let version = u64_at(data, 0);
    let path_bytes = match version {
        1 if data.len() == V1_BYTES => &data[24..],
        1 => return Err(ParseError("$I v1 must be exactly 544 bytes")),
        2 if data.len() >= 28 => {
            let count = u32::from_le_bytes(data[24..28].try_into().unwrap()) as usize;
            if !(2..=MAX_PATH_UNITS).contains(&count) || data.len() != 28 + count * 2 {
                return Err(ParseError(
                    "$I v2 UTF-16 length does not match the logical file length",
                ));
            }
            &data[28..]
        }
        2 => return Err(ParseError("$I v2 is missing its path-length field")),
        _ => {
            return Err(ParseError(
                "unsupported $I version; only v1 and v2 are accepted",
            ))
        }
    };
    let units: Vec<u16> = path_bytes
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    let end = units
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(ParseError("$I path lacks its UTF-16 terminator"))?;
    if end == 0
        || units[end + 1..].iter().any(|unit| *unit != 0)
        || (version == 2 && end + 1 != units.len())
    {
        return Err(ParseError(
            "$I path is empty or contains unexpected bytes after its terminator",
        ));
    }
    let original_path = String::from_utf16(&units[..end])
        .map_err(|_| ParseError("$I path contains malformed UTF-16"))?;
    let path = original_path.as_bytes();
    let drive_path = path.len() >= 3
        && path[0].is_ascii_alphabetic()
        && path[1] == b':'
        && matches!(path[2], b'\\' | b'/');
    if (!drive_path && !original_path.starts_with("\\\\"))
        || original_path.chars().any(char::is_control)
        || original_path.ends_with(['\\', '/'])
    {
        return Err(ParseError(
            "$I original path is not a complete absolute Windows file path",
        ));
    }
    let deleted_filetime = u64_at(data, 16);
    if deleted_filetime == 0 || deleted_filetime > MAX_FILETIME {
        return Err(ParseError(
            "$I deletion FILETIME is unset or outside years 1601..9999",
        ));
    }
    Ok(Record {
        version,
        original_size: u64_at(data, 8),
        deleted_filetime,
        deleted_unix_nanos: (i128::from(deleted_filetime) - i128::from(EPOCH_FILETIME)) * 100,
        original_path,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub fn fixture(version: u64, path: &str) -> Vec<u8> {
        let units: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
        let mut bytes = vec![
            0;
            if version == 1 {
                V1_BYTES
            } else {
                28 + units.len() * 2
            }
        ];
        bytes[0..8].copy_from_slice(&version.to_le_bytes());
        bytes[8..16].copy_from_slice(&42_u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&(EPOCH_FILETIME + 10_000_001).to_le_bytes());
        let offset = if version == 1 {
            24
        } else {
            bytes[24..28].copy_from_slice(&(units.len() as u32).to_le_bytes());
            28
        };
        for (index, unit) in units.iter().enumerate() {
            bytes[offset + index * 2..offset + index * 2 + 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn parses_both_versions_and_keeps_100ns_timestamp_precision() {
        for version in [1, 2] {
            let value = parse_i(&fixture(version, r"C:\Users\example\报告😀.txt")).unwrap();
            assert_eq!(value.version, version);
            assert_eq!(value.original_name(), "报告😀.txt");
            assert_eq!(value.original_size, 42);
            assert_eq!(value.deleted_unix_nanos, 1_000_000_100);
        }
    }

    #[test]
    fn rejects_truncated_extra_and_oversized_files() {
        for version in [1, 2] {
            let valid = fixture(version, r"C:\example.txt");
            assert!(parse_i(&valid[..valid.len() - 1]).is_err());
            let mut extra = valid;
            extra.push(0);
            assert!(parse_i(&extra).is_err());
        }
        assert!(parse_i(&[0; 23]).is_err());
        assert!(parse_i(&vec![0; MAX_RECORD_BYTES + 1]).is_err());
    }

    #[test]
    fn rejects_unknown_versions_and_mismatched_v2_path_length() {
        let mut valid = fixture(2, r"C:\example.txt");
        valid[0..8].copy_from_slice(&3_u64.to_le_bytes());
        assert!(parse_i(&valid).is_err());
        valid[0..8].copy_from_slice(&2_u64.to_le_bytes());
        for count in [0, 1, 32769, u32::MAX] {
            valid[24..28].copy_from_slice(&count.to_le_bytes());
            assert!(parse_i(&valid).is_err());
        }
    }

    #[test]
    fn rejects_invalid_utf16_missing_terminator_and_hidden_trailing_text() {
        for version in [1, 2] {
            let mut bytes = fixture(version, r"C:\x.txt");
            let start = if version == 1 { 24 } else { 28 };
            bytes[start..start + 2].copy_from_slice(&0xD800_u16.to_le_bytes());
            assert!(parse_i(&bytes).is_err());
            let mut bytes = fixture(version, r"C:\x.txt");
            for pair in bytes[start..].chunks_exact_mut(2) {
                if pair == [0, 0] {
                    pair.copy_from_slice(&[b'x', 0]);
                }
            }
            assert!(parse_i(&bytes).is_err());
        }
        let mut bytes = fixture(1, r"C:\x.txt");
        bytes[542..544].copy_from_slice(&[b'x', 0]);
        assert!(parse_i(&bytes).is_err());
    }

    #[test]
    fn rejects_unset_or_unrepresentable_filetime_but_accepts_boundaries() {
        let mut bytes = fixture(2, r"C:\x.txt");
        for ticks in [0, MAX_FILETIME + 1, u64::MAX] {
            bytes[16..24].copy_from_slice(&ticks.to_le_bytes());
            assert!(parse_i(&bytes).is_err());
        }
        for ticks in [1, MAX_FILETIME] {
            bytes[16..24].copy_from_slice(&ticks.to_le_bytes());
            assert!(parse_i(&bytes).is_ok());
        }
    }

    #[test]
    fn does_not_accept_relative_empty_or_control_character_paths() {
        for path in ["", "relative.txt", "C:\\", "C:\\line\nfile.txt"] {
            assert!(parse_i(&fixture(2, path)).is_err());
        }
        assert!(parse_i(&fixture(2, r"\\server\share\file.txt")).is_ok());
    }
}
