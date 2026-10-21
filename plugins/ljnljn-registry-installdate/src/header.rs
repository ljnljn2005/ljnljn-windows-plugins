//! REGF base-block inspection: the header fields and checksum that the
//! InstallDate report exposes before the hive tree is parsed.
//!
//! The tree itself is read by [`crate::regf`], which re-validates every
//! hbin and cell offset. This module only decides whether the file claims
//! to be a primary hive at all, and records what the base block says.

use crate::regf::BASE_BLOCK_SIZE;
use crate::time::{filetime_timestamp, hex_raw};
use lovelycarve_plugin::Timestamp;

/// Stored checksum position (just past the 127 checksum words).
const CHECKSUM_OFFSET: usize = 0x1FC;
/// The checksum covers 0x000..0x1FB: 127 little-endian u32 words.
const CHECKSUM_WORDS: usize = 127;
/// `regf` file name field (64 bytes, UTF-16LE, NUL padded).
const FILE_NAME_OFFSET: usize = 0x30;
const FILE_NAME_BYTES: usize = 64;

/// A base block that passed the structural gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub version_major: u32,
    pub version_minor: u32,
    pub file_type: u32,
    pub file_format: u32,
    pub root_cell_offset: u32,
    pub hbins_size: u32,
    pub sequence: (u32, u32),
    pub file_name: String,
    pub last_write_raw: u64,
    pub last_write: Option<Timestamp>,
    pub checksum_stored: u32,
    pub checksum_computed: u32,
}

impl Header {
    pub fn version(&self) -> String {
        format!("{}.{}", self.version_major, self.version_minor)
    }

    /// `match`, `mismatch` or `placeholder_zero` (Windows writes 0 when it
    /// did not compute one).
    pub fn checksum_state(&self) -> &'static str {
        if self.checksum_stored == 0 {
            "placeholder_zero"
        } else if self.checksum_stored == self.checksum_computed {
            "match"
        } else {
            "mismatch"
        }
    }

    pub fn checksum_text(&self) -> String {
        format!(
            "{}/{}",
            hex_raw(u64::from(self.checksum_stored), 8),
            hex_raw(u64::from(self.checksum_computed), 8)
        )
    }

    pub fn sequences_consistent(&self) -> bool {
        self.sequence.0 == self.sequence.1
    }
}

/// Why a file is not a primary registry hive this analyzer can read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HeaderError {
    pub code: &'static str,
    pub detail: String,
}

impl HeaderError {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// Reads the base block. Checksums are computed but a mismatch does not
/// reject the file: it is reported, and the hive tree parser still bounds
/// every access.
pub fn inspect(bytes: &[u8]) -> Result<Header, HeaderError> {
    if bytes.len() < BASE_BLOCK_SIZE {
        return Err(HeaderError::new(
            "HIVE_TOO_SHORT",
            format!(
                "文件长度 {} 小于 REGF base block 0x{BASE_BLOCK_SIZE:X} 字节",
                bytes.len()
            ),
        ));
    }
    if &bytes[0..4] != b"regf" {
        return Err(HeaderError::new(
            "HIVE_BAD_SIGNATURE",
            format!("base block magic 期望 regf，实际 {:02X?}", &bytes[0..4]),
        ));
    }
    let read_u32 = |offset: usize| u32::from_le_bytes(bytes[offset..offset + 4].try_into().unwrap());
    let file_type = read_u32(0x1C);
    if file_type != 0 {
        return Err(HeaderError::new(
            "HIVE_TRANSACTION_LOG",
            format!(
                "base block 文件类型 {file_type} 不是主 hive（0）；.LOG1/.LOG2 事务日志不解析"
            ),
        ));
    }
    let version_major = read_u32(0x14);
    let version_minor = read_u32(0x18);
    if version_major != 1 || version_minor > 6 {
        return Err(HeaderError::new(
            "HIVE_UNSUPPORTED_VERSION",
            format!("regf 版本 {version_major}.{version_minor} 不在支持的 1.0–1.6 范围内"),
        ));
    }
    let hbins_size = read_u32(0x28);
    if hbins_size == 0 || hbins_size % 0x1000 != 0 {
        return Err(HeaderError::new(
            "HIVE_BAD_HBINS",
            format!("hbin 区域长度 {hbins_size} 为 0 或未按 0x1000 对齐"),
        ));
    }
    let hbins_end = BASE_BLOCK_SIZE as u64 + u64::from(hbins_size);
    if hbins_end > bytes.len() as u64 {
        return Err(HeaderError::new(
            "HIVE_TRUNCATED",
            format!(
                "hbin 区域止于 0x{hbins_end:X}，超过文件长度 0x{:X}",
                bytes.len()
            ),
        ));
    }
    let root_cell_offset = read_u32(0x24);
    if u64::from(root_cell_offset) >= u64::from(hbins_size) {
        return Err(HeaderError::new(
            "HIVE_BAD_ROOT",
            format!("根键 cell 偏移 0x{root_cell_offset:X} 不在 hbin 区域内"),
        ));
    }
    let last_write_raw = u64::from_le_bytes(bytes[0x0C..0x14].try_into().unwrap());
    Ok(Header {
        version_major,
        version_minor,
        file_type,
        file_format: read_u32(0x20),
        root_cell_offset,
        hbins_size,
        sequence: (read_u32(0x04), read_u32(0x08)),
        file_name: header_file_name(bytes),
        last_write_raw,
        last_write: filetime_timestamp(last_write_raw),
        checksum_stored: read_u32(CHECKSUM_OFFSET),
        checksum_computed: checksum(bytes),
    })
}

fn header_file_name(bytes: &[u8]) -> String {
    let raw = &bytes[FILE_NAME_OFFSET..FILE_NAME_OFFSET + FILE_NAME_BYTES];
    let units: Vec<u16> = raw
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16(&units).unwrap_or_default()
}

fn checksum(bytes: &[u8]) -> u32 {
    let mut xor = 0_u32;
    for index in 0..CHECKSUM_WORDS {
        let at = index * 4;
        xor ^= u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
    }
    xor
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testhive::{build_hive, KeySpec};

    fn hive_bytes() -> Vec<u8> {
        build_hive(&KeySpec::new("SOFTWARE").child(KeySpec::new("Microsoft")))
    }

    fn patch_checksum(bytes: &mut [u8]) {
        let mut xor = 0_u32;
        for index in 0..CHECKSUM_WORDS {
            let at = index * 4;
            xor ^= u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        }
        bytes[CHECKSUM_OFFSET..CHECKSUM_OFFSET + 4].copy_from_slice(&xor.to_le_bytes());
    }

    #[test]
    fn valid_base_block_reports_fields_and_placeholder_checksum() {
        let header = inspect(&hive_bytes()).expect("valid header");
        assert_eq!(header.version(), "1.5");
        assert_eq!(header.file_type, 0);
        assert_eq!(header.checksum_state(), "placeholder_zero");
        assert!(header.sequences_consistent());
    }

    #[test]
    fn computed_checksum_matches_when_patched() {
        let mut bytes = hive_bytes();
        patch_checksum(&mut bytes);
        let header = inspect(&bytes).expect("valid header");
        assert_eq!(header.checksum_state(), "match");
        assert_eq!(header.checksum_stored, header.checksum_computed);
    }

    #[test]
    fn bad_magic_and_short_files_are_rejected() {
        let mut bytes = hive_bytes();
        bytes[0..4].copy_from_slice(b"XXXX");
        assert_eq!(inspect(&bytes).unwrap_err().code, "HIVE_BAD_SIGNATURE");
        assert_eq!(inspect(&bytes[..100]).unwrap_err().code, "HIVE_TOO_SHORT");
    }

    #[test]
    fn transaction_logs_and_out_of_range_hbins_are_rejected() {
        let mut bytes = hive_bytes();
        bytes[0x1C..0x20].copy_from_slice(&1u32.to_le_bytes());
        assert_eq!(inspect(&bytes).unwrap_err().code, "HIVE_TRANSACTION_LOG");

        let mut bytes = hive_bytes();
        bytes[0x28..0x2C].copy_from_slice(&0x00FF_0000u32.to_le_bytes());
        assert_eq!(inspect(&bytes).unwrap_err().code, "HIVE_TRUNCATED");
    }
}
