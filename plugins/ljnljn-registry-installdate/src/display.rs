//! 展示辅助：非 ASCII / 控制字符转义。
//!
//! 值名与值都按检材原样保存在 UTF-8 属性里，但表格标题使用转义形式，避免
//! 终端与导出 CSV 时被不可见字符干扰。

/// 转义规则：可打印 ASCII（0x20..=0x7E）原样；`\` 写成 `\\`；其余按
/// `\u{XXXX}`（码位十六进制）输出，控制字符同样如此。
pub fn escape_non_ascii(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            ' '..='~' => out.push(character),
            other => {
                let code = other as u32;
                if code <= 0xFFFF {
                    out.push_str(&format!("\\u{code:04x}"));
                } else {
                    out.push_str(&format!("\\u{{{code:x}}}"));
                }
            }
        }
    }
    out
}

/// 只在确实含不可打印/非 ASCII 字符时才返回转义形式，否则返回 `None`。
pub fn escaped_if_needed(text: &str) -> Option<String> {
    if text.chars().any(|character| !matches!(character, ' '..='~')) {
        Some(escape_non_ascii(text))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_passes_through_and_unicode_is_escaped() {
        assert_eq!(escape_non_ascii("ProductName"), "ProductName");
        assert_eq!(escape_non_ascii("备注"), "\\u5907\\u6ce8");
        assert_eq!(escape_non_ascii("a\\b"), "a\\\\b");
        assert_eq!(escape_non_ascii("a\nb"), "a\\u000ab");
        assert_eq!(escape_non_ascii("é"), "\\u00e9");
        assert_eq!(escaped_if_needed("Note"), None);
        assert_eq!(escaped_if_needed("Note中"), Some("Note\\u4e2d".to_owned()));
    }
}
