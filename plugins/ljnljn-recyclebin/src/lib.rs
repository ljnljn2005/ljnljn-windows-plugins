mod parser;

use lovelycarve_plugin::{export_plugin, value, AnalysisResult, Artifact, Attributes, Error, Evidence, EvidenceAnalyzer, EvidenceVolume, File, FileAnalyzer, Finding, Plugin, Result, ResultColumn, ResultNode, Severity, TimelineEvent, Value};
use parser::{parse_i, Record, MAX_RECORD_BYTES};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const MAX_ROOTS: usize = 32;
const MAX_DIRECTORIES: usize = 256;
const MAX_ENTRIES: usize = 20_000;
const MAX_RECORDS: usize = 4096;
const MAX_TEXT_BYTES: usize = 4 * 1024 * 1024;
const MAX_ENCODED_BYTES: usize = 7 * 1024 * 1024;
const SUMMARY_RESERVE_BYTES: usize = 4096;
const MAX_SOURCE_BYTES: usize = 8192;
const RECORD_TYPE: &str = "windows.recyclebin";

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.recyclebin", "Windows 回收站元数据", "0.1.0")
        .file_analyzer(RecycleFile).evidence_analyzer(RecycleEvidence)
}
export_plugin!(plugin);

struct RecycleFile;
struct RecycleEvidence;

#[derive(Default)]
struct Counts { entries: usize, records: usize, invalid: usize }

#[derive(Default)]
struct OutputBudget { text_bytes: usize, encoded_bytes: usize }

fn text_bytes(value: &Value) -> Option<usize> {
    match value {
        Value::String(text) => Some(text.as_str()?.len()),
        Value::Array(items) => items.iter().try_fold(0_usize, |total, item| total.checked_add(text_bytes(item)?)),
        Value::Map(entries) => entries.iter().try_fold(0_usize, |total, (key, value)| total.checked_add(text_bytes(key)?)?.checked_add(text_bytes(value)?)),
        _ => Some(0),
    }
}

impl OutputBudget {
    fn new(output: &AnalysisResult) -> Result<Self> {
        let mut budget = Self { text_bytes: SUMMARY_RESERVE_BYTES, encoded_bytes: SUMMARY_RESERVE_BYTES };
        budget.charge(output)?;
        Ok(budget)
    }

    // Charge each pending record/finding before committing it. The tiny empty-result
    // envelope is deliberately counted again, making this an upper estimate.
    fn charge(&mut self, pending: &AnalysisResult) -> Result<()> {
        let pending = pending.to_value();
        let text_bytes = self.text_bytes.checked_add(text_bytes(&pending).ok_or_else(|| limit("result text size overflow"))?).ok_or_else(|| limit("result text size overflow"))?;
        let encoded_bytes = self.encoded_bytes.checked_add(value::encode(&pending)?.len()).ok_or_else(|| limit("encoded result size overflow"))?;
        if text_bytes > MAX_TEXT_BYTES { return Err(limit("recycle-bin result text exceeds 4 MiB; no partial result returned")); }
        if encoded_bytes > MAX_ENCODED_BYTES { return Err(limit("estimated recycle-bin output exceeds 7 MiB; no partial result returned")); }
        self.text_bytes = text_bytes;
        self.encoded_bytes = encoded_bytes;
        Ok(())
    }
}

fn finish(output: AnalysisResult) -> Result<AnalysisResult> {
    if value::encode(&output.to_value())?.len() > MAX_ENCODED_BYTES {
        return Err(limit("encoded recycle-bin output exceeds 7 MiB; no partial result returned"));
    }
    Ok(output)
}

fn limit(message: &str) -> Error { Error::new("RESOURCE_LIMIT", message) }
fn invalid(message: impl Into<String>) -> Error { Error::new("INVALID_DATA", message) }
fn component(name: &str) -> bool { !name.is_empty() && name != "." && name != ".." && !name.contains(['/', '\\']) && !name.chars().any(char::is_control) }
fn source_bound(text: &str) -> Result<()> { if text.len() > MAX_SOURCE_BYTES { Err(limit("recycle-bin source identifier exceeds 8192 UTF-8 bytes")) } else { Ok(()) } }
fn is_i(name: &str) -> bool { name.len() > 2 && name.get(..2).is_some_and(|prefix| prefix.eq_ignore_ascii_case("$I")) }
fn paired_path(path: &str) -> Option<String> {
    let (directory, name) = path.rsplit_once('/').unwrap_or(("", path));
    if !is_i(name) || !component(name) { return None; }
    Some(format!("{}$R{}", if directory.is_empty() { String::new() } else { format!("{directory}/") }, &name[2..]))
}

fn result(include_root: bool) -> AnalysisResult {
    let columns = [("recycle.original_name", "原始文件名"), ("recycle.original_path", "原始路径"), ("recycle.original_size", "原始大小"), ("recycle.deleted_at", "删除时间 UTC"), ("recycle.companion_state", "$R 状态"), ("source.path", "元数据来源"), ("source.root", "卷")];
    AnalysisResult { nodes: vec![ResultNode { node_type: RECORD_TYPE.into(), name: "回收站记录".into(), columns: columns.into_iter().filter(|(key, _)| include_root || *key != "source.root").map(|(key, label)| ResultColumn { key: key.into(), label: label.into() }).collect() }], ..AnalysisResult::default() }
}

fn add_record(output: &mut AnalysisResult, budget: &mut OutputBudget, record: Record, mut attributes: Attributes) -> Result<()> {
    let deleted_at = OffsetDateTime::from_unix_timestamp_nanos(record.deleted_unix_nanos)
        .map_err(|_| invalid("deletion FILETIME cannot be represented"))?
        .format(&Rfc3339).map_err(|_| invalid("deletion FILETIME cannot be formatted"))?;
    attributes.insert("recycle.version", record.version);
    attributes.insert("recycle.original_name", record.original_name());
    attributes.insert("recycle.original_path", record.original_path.as_str());
    attributes.insert("recycle.original_size", record.original_size);
    attributes.insert("recycle.deleted_at", deleted_at.as_str());
    attributes.insert("recycle.deleted_filetime", record.deleted_filetime.to_string());
    let mut pending = AnalysisResult::default();
    pending.timeline.push(TimelineEvent { timestamp: deleted_at, event_type: "windows.recyclebin.deleted".into(), description: format!("回收站元数据记录删除：{}", record.original_name()), attributes: attributes.clone() });
    pending.artifacts.push(Artifact { artifact_type: RECORD_TYPE.into(), title: record.original_name().into(), value: Some(record.original_path.into()), attributes });
    budget.charge(&pending)?;
    output.timeline.append(&mut pending.timeline);
    output.artifacts.append(&mut pending.artifacts);
    Ok(())
}

fn add_invalid(output: &mut AnalysisResult, budget: &mut OutputBudget, error: Error, attributes: Attributes) -> Result<()> {
    let mut pending = AnalysisResult { findings: vec![Finding { severity: Severity::Low, title: "损坏或不支持的 $I 元数据".into(), description: error.message, attributes }], ..AnalysisResult::default() };
    budget.charge(&pending)?;
    output.findings.append(&mut pending.findings);
    Ok(())
}

fn filetime(attributes: &Attributes) -> Option<u64> { attributes.get("recycle.deleted_filetime")?.as_str()?.parse().ok() }
fn sort_results(output: &mut AnalysisResult) {
    output.artifacts.sort_by_key(|item| filetime(&item.attributes));
    output.timeline.sort_by_key(|item| filetime(&item.attributes));
}

impl FileAnalyzer for RecycleFile {
    fn analyzer(&self) -> &str { "ljnljn.recyclebin.file" }
    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        file.context().check_cancelled()?;
        source_bound(file.id())?; source_bound(file.name())?;
        if file.size() > MAX_RECORD_BYTES as u64 { return Err(limit("$I metadata exceeds 65564 bytes")); }
        let bytes = file.read(0, file.size() as usize)?;
        if bytes.len() as u64 != file.size() { return Err(invalid("short read of $I metadata")); }
        let record = parse_i(&bytes).map_err(|error| invalid(error.to_string()))?;
        file.context().check_cancelled()?;
        let mut attributes = Attributes::new();
        attributes.insert("source.file_id", file.id()); attributes.insert("source.path", file.name()); attributes.insert("source.offset", 0_u64);
        attributes.insert("recycle.companion_state", "not_checked_file_scope");
        let mut output = result(false); let mut budget = OutputBudget::new(&output)?;
        add_record(&mut output, &mut budget, record, attributes)?;
        output.summary = Some("已严格解析 1 条 $I 元数据。单文件分析不能检查对应 $R 内容是否仍在，未恢复文件内容。".into());
        finish(output)
    }
}

fn scan_directory(volume: &EvidenceVolume, path: &str, descend: bool, counts: &mut Counts, output: &mut AnalysisResult, budget: &mut OutputBudget) -> Result<()> {
    volume.context().check_cancelled()?;
    let nodes = volume.list(path)?;
    counts.entries = counts.entries.checked_add(nodes.len()).ok_or_else(|| limit("entry counter overflow"))?;
    if counts.entries > MAX_ENTRIES { return Err(limit("recycle-bin scan exceeds 20000 entries")); }
    let mut directories = Vec::new();
    for node in nodes {
        volume.context().check_cancelled()?;
        if !component(&node.name) { return Err(invalid("host returned an invalid recycle-bin path component")); }
        if node.deleted || node.kind == "link" { continue; }
        let source = format!("{path}/{}", node.name);
        source_bound(&source)?;
        if node.is_dir() && descend {
            directories.push(source);
            if directories.len() > MAX_DIRECTORIES { return Err(limit("recycle-bin scan exceeds 256 owner directories")); }
        } else if node.is_file() && is_i(&node.name) {
            counts.records += 1;
            if counts.records > MAX_RECORDS { return Err(limit("recycle-bin scan exceeds 4096 metadata records")); }
            let parsed = if node.size > MAX_RECORD_BYTES as u64 { Err(invalid("$I metadata exceeds supported length")) } else {
                let bytes = volume.read(&source, 0, Some(node.size))?;
                if bytes.len() as u64 != node.size { return Err(invalid("short read of recycle-bin metadata")); }
                parse_i(&bytes).map_err(|error| invalid(error.to_string()))
            };
            let record = match parsed {
                Ok(record) => record,
                Err(error) => {
                    counts.invalid += 1;
                    let mut attributes = Attributes::new(); attributes.insert("source.path", source.as_str()); attributes.insert("source.root", volume.root_id());
                    add_invalid(output, budget, error, attributes)?;
                    continue;
                }
            };
            let mut attributes = Attributes::new(); attributes.insert("source.path", source.as_str()); attributes.insert("source.root", volume.root_id()); attributes.insert("source.offset", 0_u64);
            let companion = paired_path(&source).ok_or_else(|| invalid("cannot determine $R companion path"))?;
            attributes.insert("recycle.companion_path", companion.as_str());
            match volume.stat(&companion)? {
                Some(node) if !node.deleted && (node.is_file() || node.is_dir()) => {
                    attributes.insert("recycle.companion_state", if node.is_file() { "present_file" } else { "present_directory" });
                    attributes.insert("recycle.companion_present", true);
                    if node.is_file() {
                        attributes.insert("recycle.companion_size", node.size);
                        attributes.insert("recycle.size_matches", node.size == record.original_size);
                    }
                }
                _ => { attributes.insert("recycle.companion_state", "missing"); attributes.insert("recycle.companion_present", false); }
            }
            add_record(output, budget, record, attributes)?;
        }
    }
    directories.sort();
    for directory in directories { scan_directory(volume, &directory, false, counts, output, budget)?; }
    Ok(())
}

impl EvidenceAnalyzer for RecycleEvidence {
    fn analyzer(&self) -> &str { "ljnljn.recyclebin.evidence" }
    fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult> {
        let roots = evidence.roots()?;
        if roots.len() > MAX_ROOTS { return Err(limit("recycle-bin scan exceeds 32 volumes")); }
        let mut output = result(true); let mut budget = OutputBudget::new(&output)?;
        let mut counts = Counts::default(); let mut scanned = 0;
        for root in roots {
            evidence.context().check_cancelled()?;
            source_bound(&root.root_id)?;
            let volume = evidence.volume(&root.root_id);
            if !volume.is_dir("$Recycle.Bin")? { continue; }
            scanned += 1;
            scan_directory(&volume, "$Recycle.Bin", true, &mut counts, &mut output, &mut budget)?;
        }
        if counts.records > 0 && output.artifacts.is_empty() { return Err(invalid(format!("发现 {} 个 $I 候选，全部损坏或不支持；未产生有效记录", counts.records))); }
        sort_results(&mut output);
        output.summary = Some(format!("扫描 {} 个回收站卷；有效 {} 条，损坏/不支持 {} 条。只解析 $I 元数据与检查 $R 存在性，未恢复内容；损坏记录见发现项。", scanned, output.artifacts.len(), counts.invalid));
        finish(output)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn companion_path_preserves_owner_and_never_resolves_original_path() {
        assert_eq!(paired_path("$Recycle.Bin/S-1-5-21-example/$IABC123.txt").unwrap(), "$Recycle.Bin/S-1-5-21-example/$RABC123.txt");
        assert!(paired_path("plain.txt").is_none()); assert!(!component("../escape")); assert!(!component("x\\y"));
    }

    #[test]
    fn record_result_has_source_fields_timeline_and_unverified_companion_state() {
        let record = parse_i(&parser::tests::fixture(2, r"C:\example.txt")).unwrap();
        let mut attributes = Attributes::new(); attributes.insert("source.path", "$IABC123.txt"); attributes.insert("recycle.companion_state", "not_checked_file_scope");
        let mut output = result(false); let mut budget = OutputBudget::new(&output).unwrap(); add_record(&mut output, &mut budget, record, attributes).unwrap();
        assert_eq!(output.artifacts.len(), 1); assert_eq!(output.timeline.len(), 1);
        let item = &output.artifacts[0];
        assert_eq!(item.attributes.get("recycle.original_size").and_then(|value| value.as_u64()), Some(42));
        assert_eq!(item.attributes.get("source.path").and_then(|value| value.as_str()), Some("$IABC123.txt"));
        assert_eq!(output.timeline[0].timestamp, "1970-01-01T00:00:01.0000001Z");
        assert!(!item.attributes.contains_key("recycle.companion_present"));
        assert!(!output.nodes[0].columns.iter().any(|column| column.key == "source.root"));
    }

    #[test]
    fn sorts_early_filetimes_and_fractional_timestamps_numerically() {
        let ticks = [116_444_736_010_000_001_u64, 10, 116_444_736_010_000_000, 1, 9];
        let mut output = result(true);
        let mut budget = OutputBudget::new(&output).unwrap();
        for tick in ticks {
            let mut bytes = parser::tests::fixture(2, r"C:\example.txt");
            bytes[16..24].copy_from_slice(&tick.to_le_bytes());
            add_record(&mut output, &mut budget, parse_i(&bytes).unwrap(), Attributes::new()).unwrap();
        }
        sort_results(&mut output);
        let expected = vec![1, 9, 10, 116_444_736_010_000_000, 116_444_736_010_000_001];
        assert_eq!(output.artifacts.iter().map(|item| filetime(&item.attributes).unwrap()).collect::<Vec<_>>(), expected);
        assert_eq!(output.timeline.iter().map(|item| filetime(&item.attributes).unwrap()).collect::<Vec<_>>(), expected);
    }

    #[test]
    fn cumulative_long_paths_fail_before_record_count_limit_without_appending_failed_record() {
        let path = format!("C:\\{}", "名".repeat(32_760));
        let record = parse_i(&parser::tests::fixture(2, &path)).unwrap();
        let mut output = result(true);
        let mut budget = OutputBudget::new(&output).unwrap();
        let mut rejected = false;
        for _ in 0..MAX_RECORDS {
            let before = (output.artifacts.len(), output.timeline.len(), budget.text_bytes, budget.encoded_bytes);
            if let Err(error) = add_record(&mut output, &mut budget, record.clone(), Attributes::new()) {
                assert_eq!(error.code, "RESOURCE_LIMIT");
                assert_eq!((output.artifacts.len(), output.timeline.len(), budget.text_bytes, budget.encoded_bytes), before);
                assert!(output.artifacts.len() < MAX_RECORDS);
                rejected = true;
                break;
            }
        }
        assert!(rejected, "long-path results must hit an output budget before 4096 records");
        assert!(value::encode(&output.to_value()).unwrap().len() < MAX_ENCODED_BYTES);
    }

    #[test]
    fn finding_text_and_estimated_encoding_are_both_budgeted() {
        let mut output = result(true);
        let mut budget = OutputBudget::new(&output).unwrap();
        budget.text_bytes = MAX_TEXT_BYTES - 1;
        let error = add_invalid(&mut output, &mut budget, invalid("bad metadata"), Attributes::new()).unwrap_err();
        assert_eq!(error.code, "RESOURCE_LIMIT");
        assert!(output.findings.is_empty());
        budget.text_bytes = 0;
        budget.encoded_bytes = MAX_ENCODED_BYTES - 1;
        let record = parse_i(&parser::tests::fixture(2, r"C:\example.txt")).unwrap();
        let error = add_record(&mut output, &mut budget, record, Attributes::new()).unwrap_err();
        assert_eq!(error.code, "RESOURCE_LIMIT");
        assert!(output.artifacts.is_empty());
        assert!(output.timeline.is_empty());
    }

    #[test]
    fn final_messagepack_size_rejects_large_summary_and_accepts_exact_limit() {
        let mut output = AnalysisResult { summary: Some(String::new()), ..AnalysisResult::default() };
        // A long string uses a five-byte MessagePack header, four bytes more
        // than the empty fixstr in the baseline result.
        let baseline = value::encode(&output.to_value()).unwrap().len();
        output.summary = Some("x".repeat(MAX_ENCODED_BYTES - baseline - 4));
        assert_eq!(value::encode(&output.to_value()).unwrap().len(), MAX_ENCODED_BYTES);
        let mut output = finish(output).unwrap();
        output.summary.as_mut().unwrap().push('x');
        assert_eq!(finish(output).unwrap_err().code, "RESOURCE_LIMIT");
        assert!(source_bound(&"x".repeat(MAX_SOURCE_BYTES)).is_ok());
        assert_eq!(source_bound(&"x".repeat(MAX_SOURCE_BYTES + 1)).unwrap_err().code, "RESOURCE_LIMIT");
    }
}
