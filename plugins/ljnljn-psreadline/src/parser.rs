use regex::Regex;
use std::collections::BTreeSet;
use std::sync::OnceLock;

pub const MAX_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_COMMANDS: usize = 100_000;
pub const MAX_MATCHES: usize = 4_000;

#[derive(Debug, PartialEq)]
pub struct Command {
    pub index: usize,
    pub line: usize,
    pub text: String,
    pub urls: Vec<String>,
}

#[derive(Debug)]
pub struct History {
    pub commands: usize,
    pub matches: Vec<Command>,
}

fn decode(bytes: &[u8]) -> Result<String, String> {
    if bytes.len() > MAX_BYTES { return Err("history exceeds the 4 MiB input limit".into()); }
    if bytes.starts_with(&[0xff, 0xfe]) || bytes.starts_with(&[0xfe, 0xff]) {
        let little = bytes[0] == 0xff;
        let bytes = &bytes[2..];
        if bytes.len() % 2 != 0 { return Err("truncated UTF-16 history".into()); }
        let words: Vec<u16> = bytes.chunks_exact(2).map(|pair| {
            if little { u16::from_le_bytes([pair[0], pair[1]]) }
            else { u16::from_be_bytes([pair[0], pair[1]]) }
        }).collect();
        let decoded = String::from_utf16(&words).map_err(|_| String::from("invalid UTF-16 history"))?;
        if decoded.contains('\0') { return Err("NUL in UTF-16 history".into()); }
        Ok(decoded)
    } else {
        let bytes = bytes.strip_prefix(&[0xef, 0xbb, 0xbf]).unwrap_or(bytes);
        let text = std::str::from_utf8(bytes).map_err(|_| "history is not UTF-8 or BOM UTF-16")?;
        if text.contains('\0') { return Err("NUL in history; select a text history file".into()); }
        Ok(text.to_owned())
    }
}

fn urls(text: &str) -> Vec<String> {
    static URL: OnceLock<Regex> = OnceLock::new();
    let pattern = URL.get_or_init(|| Regex::new(r#"(?i)https?://[^\s"'\x60<>]+"#).expect("constant URL pattern"));
    let mut seen = BTreeSet::new();
    pattern.find_iter(text).filter_map(|found| {
        let mut url = found.as_str();
        loop {
            let Some(last) = url.chars().last() else { break };
            let close = match last { ')' => Some('('), ']' => Some('['), '}' => Some('{'), _ => None };
            let strip = close.is_some_and(|open| url.matches(last).count() > url.matches(open).count())
                || matches!(last, ',' | ';');
            if !strip { break; }
            url = &url[..url.len() - last.len_utf8()];
        }
        let (_, rest) = url.split_once("://")?;
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
        if authority.is_empty() || authority.starts_with('.') { return None; }
        seen.insert(url.to_owned()).then(|| url.to_owned())
    }).collect()
}

pub fn parse(bytes: &[u8]) -> Result<History, String> {
    let text = decode(bytes)?;
    let mut result = History { commands: 0, matches: Vec::new() };
    let mut pending = String::new();
    let mut first_line = 0;
    for (offset, line) in text.lines().enumerate() {
        if offset > MAX_COMMANDS * 8 { return Err("history has too many physical lines".into()); }
        if pending.is_empty() && line.trim().is_empty() { continue; }
        if pending.is_empty() { first_line = offset + 1; }
        let continued = line.chars().rev().take_while(|c| *c == char::from(96)).count() % 2 == 1;
        pending.push_str(if continued { &line[..line.len() - 1] } else { line });
        if pending.len() > 65_536 { return Err("one history command exceeds 64 KiB".into()); }
        if continued { pending.push('\n'); continue; }
        record(&mut result, first_line, std::mem::take(&mut pending))?;
    }
    if !pending.is_empty() { return Err("history ends in an incomplete multiline command".into()); }
    Ok(result)
}

fn record(result: &mut History, line: usize, text: String) -> Result<(), String> {
    result.commands += 1;
    if result.commands > MAX_COMMANDS { return Err("history exceeds 100000 commands".into()); }
    let urls = urls(&text);
    if !urls.is_empty() {
        if result.matches.len() == MAX_MATCHES {
            return Err("history exceeds 4000 URL-bearing commands; no partial count returned".into());
        }
        result.matches.push(Command { index: result.commands, line, text, urls });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_commands_not_links_or_unique_commands() {
        let parsed = parse(b"Get-Date\ncurl https://a.example/x https://a.example/x https://b.example/?q=a%20b\ncurl https://a.example/x\n").unwrap();
        assert_eq!(parsed.commands, 3);
        assert_eq!(parsed.matches.len(), 2);
        assert_eq!(parsed.matches[0].urls, ["https://a.example/x", "https://b.example/?q=a%20b"]);
        assert_eq!(parsed.matches[1].index, 3);
    }
    #[test]
    fn handles_multiline_and_literal_escaped_backticks() {
        let text = format!("Invoke-WebRequest {}\n'https://a.example/x'\nWrite-Output {}{}\ncurl https://b.example/\n", char::from(96), char::from(96), char::from(96));
        let parsed = parse(text.as_bytes()).unwrap();
        assert_eq!(parsed.commands, 3);
        assert_eq!(parsed.matches[0].line, 1);
        assert_eq!(parsed.matches[0].index, 1);
        assert_eq!(parsed.matches[1].line, 4);
    }
    #[test]
    fn punctuation_and_empty_authorities() {
        let parsed = parse(b"echo (https://a.example/x_(y)), 'https://b.example/?q=1&v=2' http:///bad\n").unwrap();
        assert_eq!(parsed.matches[0].urls, ["https://a.example/x_(y)", "https://b.example/?q=1&v=2"]);
    }
    #[test]
    fn preserves_unicode_and_supports_bom_utf16() {
        let mut bytes = vec![0xff, 0xfe];
        for word in "echo https://example.test/路径\n".encode_utf16() { bytes.extend(word.to_le_bytes()); }
        assert_eq!(parse(&bytes).unwrap().matches[0].urls[0], "https://example.test/路径");
        bytes.push(0);
        assert!(parse(&bytes).is_err());
    }
    #[test]
    fn invalid_or_incomplete_input_is_not_a_zero_count() {
        assert!(parse(&[0xff]).is_err());
        assert!(parse(&[0, 0]).is_err());
        assert!(parse(format!("curl {}", char::from(96)).as_bytes()).is_err());
        assert!(parse(&vec![b'a'; MAX_BYTES + 1]).is_err());
        assert_eq!(parse(b" \nGet-Date\n").unwrap().matches.len(), 0);
    }
}
