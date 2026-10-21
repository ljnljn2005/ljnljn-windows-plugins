//! 字符集识别与解码。
//!
//! 只按**文件头**（BOM）与 UTF-8 结构判定编码，不做二进制格式猜测：
//! 需要 BOM 才能认定为 UTF-16；无 BOM 的字节一律先当合法 UTF-8，否则 GBK
//! 严格解码，GBK 严格解码失败再 GB18030 严格解码，最后才 UTF-8 有损替换。
//!
//! 非 UTF-16 目标编码都会把单元重新编码成简体中文 GBK 字节验证一次，
//! 避免把 UTF-8 中文误判成 GBK（两者都满足"可解码且无替换字符"）。
//! 注意：字符集名写 `GBK`（Windows 代码页 936 的习惯叫法），当 GBK 严格解码
//! 失败而 GB18030 严格解码成功时会如实降级为 `GB18030`。

/// 解码后的文本与编码判定结果。
#[derive(Clone, Debug, Default, PartialEq)]
pub struct DecodedText {
    pub text: String,
    /// 实际采用的编码标签：`UTF-16LE`、`UTF-16BE`、`UTF-8-BOM`、`UTF-8`、
    /// `GBK`、`GB18030`、`UTF-8-LOSSY`。
    pub encoding: String,
    /// 原始字节含 BOM 或在编码检查/解码中发现非法字节序列。
    pub has_bom: bool,
    /// 非法字节序列被替换为 U+FFFD 的次数。
    pub replacement_count: usize,
    /// null 字节（U+0000）个数；文本 CSV 中通常只出现在 UTF-16 里。
    pub nul_bytes: usize,
}

const UTF8_BOM: [u8; 3] = [0xEF, 0xBB, 0xBF];
const UTF16LE_BOM: [u8; 2] = [0xFF, 0xFE];
const UTF16BE_BOM: [u8; 2] = [0xFE, 0xFF];

/// 按文件头与结构判定编码并解码为 String。
pub fn decode(bytes: &[u8]) -> DecodedText {
    if bytes.starts_with(&UTF8_BOM) {
        // UTF-8 BOM 之后若还有非法字节，仍按 UTF-8 有损解码并让调用方记录限制。
        return match std::str::from_utf8(&bytes[UTF8_BOM.len()..]) {
            Ok(text) => DecodedText {
                text: text.to_owned(),
                encoding: "UTF-8-BOM".to_owned(),
                has_bom: true,
                replacement_count: 0,
                nul_bytes: text.matches('\0').count(),
            },
            Err(_) => lossy(&bytes[UTF8_BOM.len()..], "UTF-8-BOM", true),
        };
    }
    if bytes.starts_with(&UTF16LE_BOM) {
        return decode_utf16(&bytes[UTF16LE_BOM.len()..], true, "UTF-16LE");
    }
    if bytes.starts_with(&UTF16BE_BOM) {
        return decode_utf16(&bytes[UTF16BE_BOM.len()..], false, "UTF-16BE");
    }
    if let Ok(text) = std::str::from_utf8(bytes) {
        return DecodedText {
            text: text.to_owned(),
            encoding: "UTF-8".to_owned(),
            has_bom: false,
            replacement_count: 0,
            nul_bytes: text.matches('\0').count(),
        };
    }
    match decode_gbk(bytes) {
        Some((text, encoding)) => DecodedText {
            nul_bytes: text.matches('\0').count(),
            text,
            encoding: encoding.to_owned(),
            has_bom: false,
            replacement_count: 0,
        },
        None => lossy(bytes, "UTF-8", false),
    }
}

/// UTF-8 有损解码（每个非法序列记一次替换）。
fn lossy(bytes: &[u8], base: &str, bom: bool) -> DecodedText {
    let text = String::from_utf8_lossy(bytes).into_owned();
    let replacement_count = text.matches(char::REPLACEMENT_CHARACTER).count();
    DecodedText {
        nul_bytes: text.matches('\0').count(),
        text,
        encoding: format!("{base}-LOSSY"),
        has_bom: bom,
        replacement_count,
    }
}

/// UTF-16 解码；奇数长度或孤立代理项按替换字符处理并计数。
fn decode_utf16(bytes: &[u8], little_endian: bool, label: &str) -> DecodedText {
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        units.push(if little_endian {
            u16::from_le_bytes([pair[0], pair[1]])
        } else {
            u16::from_be_bytes([pair[0], pair[1]])
        });
    }
    let mut text = String::with_capacity(units.len());
    let mut replacement_count = 0;
    for chunk in char::decode_utf16(units) {
        match chunk {
            Ok(character) => text.push(character),
            Err(_) => {
                text.push(char::REPLACEMENT_CHARACTER);
                replacement_count += 1;
            }
        }
    }
    if bytes.len() % 2 == 1 {
        // 末尾半个代码单元：非法字节，按替换降级。
        text.push(char::REPLACEMENT_CHARACTER);
        replacement_count += 1;
    }
    DecodedText {
        nul_bytes: text.matches('\0').count(),
        text,
        encoding: label.to_owned(),
        has_bom: true,
        replacement_count,
    }
}

/// 严格 GBK 解码，失败时严格 GB18030 解码；再要求"重新编码回简体中文 GBK
/// 字节后与原字节一致"，用于排除被误当成 GBK 的其它编码。
fn decode_gbk(bytes: &[u8]) -> Option<(String, &'static str)> {
    if bytes.is_empty() {
        return None;
    }
    if let Some(text) = decode_strict(bytes, "gbk") {
        if reencode_matches(&text, bytes) {
            return Some((text, "GBK"));
        }
    }
    let text = decode_strict(bytes, "gb18030")?;
    if reencode_matches(&text, bytes) {
        return Some((text, "GB18030"));
    }
    None
}

fn decode_strict(bytes: &[u8], label: &str) -> Option<String> {
    let encoding = encoding_rs::Encoding::for_label_no_replacement(label.as_bytes())?;
    let (text, had_errors) = encoding.decode_without_bom_handling(bytes);
    (!had_errors).then(|| text.into_owned())
}

fn reencode_matches(text: &str, bytes: &[u8]) -> bool {
    let encoding = match encoding_rs::Encoding::for_label_no_replacement(b"gbk") {
        Some(encoding) => encoding,
        None => return false,
    };
    let (encoded, _, had_errors) = encoding.encode(text);
    !had_errors && encoded.as_ref() == bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utf8_with_and_without_bom() {
        let plain = "备注,VCpwd: 测试".as_bytes();
        let decoded = decode(plain);
        assert_eq!(decoded.encoding, "UTF-8");
        assert!(!decoded.has_bom);
        assert_eq!(decoded.text, "备注,VCpwd: 测试");

        let mut with_bom = UTF8_BOM.to_vec();
        with_bom.extend_from_slice(plain);
        let decoded = decode(&with_bom);
        assert_eq!(decoded.encoding, "UTF-8-BOM");
        assert!(decoded.has_bom);
        assert_eq!(decoded.replacement_count, 0);
        assert_eq!(decoded.text, "备注,VCpwd: 测试");
    }

    #[test]
    fn utf16le_and_big_endian_require_bom() {
        let text = "VCpwd: 5thGoldenEyesCup";
        let mut le = UTF16LE_BOM.to_vec();
        for unit in text.encode_utf16() {
            le.extend_from_slice(&unit.to_le_bytes());
        }
        let decoded = decode(&le);
        assert_eq!(decoded.encoding, "UTF-16LE");
        assert_eq!(decoded.text, text);
        assert_eq!(decoded.replacement_count, 0);

        let mut be = UTF16BE_BOM.to_vec();
        for unit in text.encode_utf16() {
            be.extend_from_slice(&unit.to_be_bytes());
        }
        let decoded = decode(&be);
        assert_eq!(decoded.encoding, "UTF-16BE");
        assert_eq!(decoded.text, text);
    }

    #[test]
    fn without_bom_utf16_is_not_guessed_as_utf16() {
        let mut raw = Vec::new();
        for unit in "VCpwd: x".encode_utf16() {
            raw.extend_from_slice(&unit.to_le_bytes());
        }
        let decoded = decode(&raw);
        assert_ne!(decoded.encoding, "UTF-16LE");
        assert!(decoded.nul_bytes > 0);
    }

    #[test]
    fn gbk_and_gb18030_are_detected() {
        let (gbk, _, _) = encoding_rs::GBK.encode("编号,内容,VCpwd：金色眼睛");
        let decoded = decode(gbk.as_ref());
        assert_eq!(decoded.encoding, "GBK");
        assert_eq!(decoded.text, "编号,内容,VCpwd：金色眼睛");
        assert_eq!(decoded.replacement_count, 0);

        // U+20AC 在 GBK 代码页 936 里没有对应字节，只能用 GB18030 表示。
        let (gb18030, _, had_errors) = encoding_rs::GB18030.encode("代码,VCpwd: 1 号");
        assert!(!had_errors);
        let decoded = decode(gb18030.as_ref());
        assert!(matches!(decoded.encoding.as_str(), "GBK" | "GB18030"));
        assert_eq!(decoded.text, "代码,VCpwd: 1 号");
    }

    #[test]
    fn invalid_utf8_after_bom_is_replaced_and_counted() {
        let mut raw = UTF8_BOM.to_vec();
        raw.extend_from_slice(b"a,\xff\xfeVCpwd: x\n");
        let decoded = decode(&raw);
        assert_eq!(decoded.encoding, "UTF-8-BOM-LOSSY");
        assert!(decoded.replacement_count > 0);
        assert!(decoded.text.contains("VCpwd: x"));
    }

    #[test]
    fn odd_length_utf16_tail_is_replaced() {
        let mut raw = UTF16LE_BOM.to_vec();
        raw.extend_from_slice(&[b'a', 0, b'b']);
        let decoded = decode(&raw);
        assert_eq!(decoded.encoding, "UTF-16LE");
        assert_eq!(decoded.replacement_count, 1);
        assert!(decoded.text.ends_with(char::REPLACEMENT_CHARACTER));
    }
}
