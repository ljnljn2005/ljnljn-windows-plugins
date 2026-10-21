//! VCpwd credential candidates in Sticky Notes CSV/TSV exports (LPP v2).
//!
//! The charset, CSV and extraction code is unchanged from the LPP v1 plugin:
//! BOM/UTF-8/GBK/GB18030 decoding, comma/tab delimiter detection, RFC 4180
//! quoting, case-insensitive `VCpwd` keys with `:` / `=` / `：` separators,
//! value deduplication and occurrence counting.
//!
//! The analyzer reads files the user selected. A file larger than the input
//! cap is parsed up to the cap with an explicit warning and limitation, as in
//! v1; a short read is a warning, never a silent partial result. No field is
//! a timestamp: the extracted notes carry no reliable time value.

mod charset;
mod csv;
mod engine;

#[cfg(test)]
mod tests;

use lovelycarve_plugin::{export_plugin, FileRef, Plugin, Record, Result, Run};

use crate::engine::{FileReport, MAX_INPUT_BYTES};

/// Bytes read from the host per call.
const READ_CHUNK: usize = 1024 * 1024;
/// v2 text fields hold at most 256 KiB; longer credential values are skipped
/// with a warning instead of failing the whole run.
const MAX_VALUE_BYTES: usize = 256 * 1024;

#[derive(Record)]
#[record(
    id = "stickynotes.file",
    label = "便笺 CSV 文件汇总",
    title = "{source_file}"
)]
struct StickyFile {
    #[field(label = "来源文件", key)]
    source_file: String,
    #[field(label = "编码")]
    encoding: String,
    #[field(
        label = "分隔符",
        kind = "enum",
        choices = "comma=逗号,tab=制表符,unknown=未知"
    )]
    delimiter: String,
    #[field(label = "记录数")]
    record_count: usize,
    #[field(label = "凭据值数")]
    credential_count: usize,
    #[field(label = "未解析行数")]
    unparsed_row_count: usize,
    #[field(label = "含表头")]
    has_header: bool,
    #[field(label = "来源大小", kind = "size")]
    source_size: u64,
    #[field(label = "引号包裹值数")]
    quoted_values: usize,
    #[field(label = "含冒号值数")]
    colon_values: usize,
    #[field(label = "含逗号值数")]
    comma_values: usize,
    #[field(label = "限制说明", kind = "list")]
    limitations: Vec<String>,
}

#[derive(Record)]
#[record(
    id = "stickynotes.credential",
    label = "VCpwd 凭据候选",
    title = "VCpwd · 第 {row_index} 行"
)]
struct StickyCredential {
    #[field(label = "凭据值", key)]
    value: String,
    #[field(label = "原始单元格")]
    raw_cell: String,
    #[field(label = "行号")]
    row_index: usize,
    #[field(label = "列名/列序号")]
    column: String,
    #[field(label = "是否截断")]
    truncated: bool,
    #[field(label = "出现次数")]
    occurrences: usize,
    #[field(label = "出现行号", kind = "list")]
    occurrence_rows: Vec<String>,
    #[field(label = "出现列", kind = "list")]
    occurrence_columns: Vec<String>,
    #[field(label = "值后续键值对数")]
    trailing_pairs: usize,
    #[field(label = "CRLF 行")]
    crlf_row: bool,
}

fn delimiter_choice(delimiter: &str) -> &'static str {
    match delimiter {
        "," => "comma",
        "\t" => "tab",
        _ => "unknown",
    }
}

/// Reads at most `cap` bytes, one host call at a time. Returns the bytes and
/// whether the file is larger than the cap.
fn read_bytes(file: &FileRef, cap: usize) -> Result<(Vec<u8>, bool)> {
    let size = usize::try_from(file.size()).unwrap_or(usize::MAX);
    let limit = size.min(cap);
    let mut bytes = Vec::with_capacity(limit.min(READ_CHUNK * 4));
    while bytes.len() < limit {
        let want = (limit - bytes.len()).min(READ_CHUNK);
        let offset = bytes.len() as u64;
        let chunk = file.read_at(offset, want)?;
        if chunk.is_empty() {
            break;
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok((bytes, size > cap))
}

fn emit_report(run: &Run, file: &FileRef, report: &FileReport) -> Result<usize> {
    let oversized = report
        .credentials
        .iter()
        .filter(|credential| credential.value.len() > MAX_VALUE_BYTES)
        .count();
    let mut limitations = report.limitations.clone();
    if oversized > 0 {
        limitations.push(format!(
            "{oversized} 个凭据值超过单字段 256 KiB 上限，未输出；已产生 VALUE_TOO_LARGE 告警"
        ));
    }

    run.record(&StickyFile {
        source_file: report.source_file.clone(),
        encoding: report.encoding.clone(),
        delimiter: delimiter_choice(&report.delimiter).to_owned(),
        record_count: report.record_count,
        credential_count: report.credential_count,
        unparsed_row_count: report.unparsed_row_count,
        has_header: report.has_header,
        source_size: file.size(),
        quoted_values: report.quoted_values,
        colon_values: report.colon_values,
        comma_values: report.comma_values,
        limitations,
    })
    .from(file)
    .at(0, file.size())
    .note(report.source_file.clone())
    .emit()?;

    let mut emitted = 0usize;
    for credential in &report.credentials {
        if credential.value.len() > MAX_VALUE_BYTES {
            run.warn_file(
                file,
                "VALUE_TOO_LARGE",
                format!(
                    "第 {} 行：凭据值 {} 字节，超过单字段 256 KiB 上限，已跳过该条记录",
                    credential.row_index,
                    credential.value.len()
                ),
            )?;
            continue;
        }
        let column = credential.column_label();
        run.record(&StickyCredential {
            value: credential.value.clone(),
            raw_cell: credential.raw_cell.clone(),
            row_index: credential.row_index,
            column: column.clone(),
            truncated: credential.truncated,
            occurrences: credential.occurrences,
            occurrence_rows: credential
                .occurrence_locations
                .iter()
                .map(|item| item.row_index.to_string())
                .collect(),
            occurrence_columns: credential
                .occurrence_locations
                .iter()
                .map(|item| item.column.label())
                .collect(),
            trailing_pairs: credential.trailing_pairs,
            crlf_row: credential.crlf_row,
        })
        .from(file)
        .note(format!("row {}, column {column}", credential.row_index))
        .emit()?;
        emitted += 1;
    }
    Ok(emitted)
}

fn stickynotes_vcpwd(run: &Run) -> Result<()> {
    let mut files = 0usize;
    let mut credentials = 0usize;
    let mut skipped = 0usize;

    for file in run.inputs() {
        run.check_cancelled()?;
        files += 1;
        let (bytes, truncated) = match read_bytes(file, MAX_INPUT_BYTES) {
            Ok(read) => read,
            Err(error) => {
                skipped += 1;
                run.warn_file(file, &error.code, error.message)?;
                continue;
            }
        };
        let expected = file.size().min(MAX_INPUT_BYTES as u64);
        if bytes.len() as u64 != expected {
            skipped += 1;
            run.warn_file(
                file,
                "SHORT_READ",
                format!(
                    "{}: 读取 {} / {} 字节，拒绝在不完整数据上解析",
                    file.name(),
                    bytes.len(),
                    expected
                ),
            )?;
            continue;
        }

        let mut report = engine::analyze_bytes(file.name(), &bytes);
        if truncated {
            let note = format!("文件大于 {MAX_INPUT_BYTES} 字节，仅解析前 {MAX_INPUT_BYTES} 字节");
            if !report.limitations.contains(&note) {
                report.limitations.push(note.clone());
            }
            run.warn_file(file, "INPUT_TRUNCATED", format!("{}: {note}", file.name()))?;
        }
        run.progress(
            files as u64,
            Some(run.inputs().len() as u64),
            Some(file.name()),
        )?;
        if report.unparsed_row_count > 0 {
            run.warn_file(
                file,
                "UNPARSED_ROWS",
                format!(
                    "{}: {} 行未解析（CSV 结构异常或字段数与首条记录不一致），详见 limitations",
                    file.name(),
                    report.unparsed_row_count
                ),
            )?;
        }
        credentials += emit_report(run, file, &report)?;
    }

    if run.inputs().is_empty() {
        run.warn(
            "INPUT_NOT_FOUND",
            "未选择便笺 CSV/TSV 文件；请选择火眼导出的 data.csv 或同构文本",
        )?;
    }
    run.set_summary(format!(
        "读取 {files} 个文件，输出 VCpwd 凭据值 {credentials} 个（去重后），跳过 {skipped} 个；未覆盖 VeraCrypt 挂载、密码校验与卷内文件计数"
    ));
    Ok(())
}

fn plugin() -> Plugin {
    Plugin::new("org.ljnljn.stickynotes-vcpwd")
        .record::<StickyFile>()
        .record::<StickyCredential>()
        .analyzer("stickynotes_vcpwd", stickynotes_vcpwd)
}

export_plugin!(plugin);
