//! Windows 注册表 hive 的 InstallDate 离线分析插件（LovelyCarve / LPP v1）。
//!
//! 输入（只读，两种宿主句柄）：
//! * `FileAnalyzer`：`analyzer.analyze` 传入的单个 hive 文件句柄 —— 用户在文件列表
//!   里选中已提取的 `SOFTWARE`（或任意以文件形式给出的 regf hive）。
//! * `EvidenceAnalyzer`：检材级分析，在可浏览卷内定位
//!   `Windows/System32/config/SOFTWARE`（并兜底扫描同名 `.hive` 副本）。
//!
//! 插件不解析 E01/分区表，也不读取检材真实路径：镜像挂载与 hive 提取由上层完成，
//! 本插件只接收逻辑句柄。解析过程不写入 hive、不执行检材内的程序、不联网。
//!
//! 解析链：`regf` 文件头（魔数 / 版本 / 文件类型 / bins 长度 / 校验和）→ hbin →
//! nk/vk 树 → `Microsoft\Windows NT\CurrentVersion`（键名大小写不敏感）→
//! `InstallDate`（REG_DWORD 或十进制字符串 REG_SZ）→ Unix 秒解释成 UTC ISO8601，
//! 同时输出原值、十六进制原值与“本地时区未知”的原样表示，不猜测时区。
//!
//! 产物类型（`artifact_type`）：
//!   `installdate.hive`          hive 文件头与 regf 校验结果
//!   `installdate.key`           目标键定位（实际路径、缺失段、cell 偏移）
//!   `installdate.install_date`  InstallDate 原值 / 十六进制 / UTC / 原样表示
//!   `installdate.aux_value`     只读辅助值（ProductName / CurrentBuild / …）
//!   `installdate.evidence`      证据来源与定位线索（cell 偏移与文件偏移）
//!   `installdate.warning`       解析告警（值越界、类型不支持、截断、多匹配…）
//!   `installdate.limitation`    覆盖范围与首版限制

mod display;
mod extract;
mod regf;
mod render;
mod time;

/// 合成 hive 构建器（单元测试与 `tools/host-sim` 的 `--make-fixture` 共用）。
pub mod synth;

#[cfg(test)]
mod tests;

use lovelycarve_plugin::{
    export_plugin, AnalysisResult, Evidence, EvidenceAnalyzer, EvidenceVolume, File, FileAnalyzer,
    LogLevel, Plugin, Result, Value,
};

use crate::extract::{analyze_hive, HiveReport, SourceInfo};
use crate::regf::ReadAt;

pub use crate::extract::{
    AuxValue, HeaderCheck, HiveReport as Report, InstallDateValue, InstallState, KeyLookup,
    NoteLevel, ReportNote, SourceInfo as HiveSource, AUX_VALUES, LIMITATIONS, TARGET_KEY,
    TARGET_VALUE,
};
pub use crate::regf::{
    compute_checksum, BaseBlock, ErrorKind, Hive, HiveError, HiveValue, KeyNode, ReadAt as HiveReadAt,
    SliceReader, ValueData, ValueType, BASE_BLOCK_SIZE, NO_CELL,
};
pub use crate::render::{
    artifact_types, result_nodes, ART_AUX_VALUE, ART_EVIDENCE, ART_HIVE, ART_INSTALL_DATE, ART_KEY,
    ART_LIMITATION, ART_WARNING,
};
pub use crate::time::{
    filetime_to_iso8601, hex_raw, parse_decimal_text, plausibility, raw_display, unix_to_iso8601,
    ParsedText, Plausibility, MAX_UNIX_SECONDS,
};

/// 分析器基础名；文件与检材能力必须使用不同 analyzer 名，否则宿主会判重复。
pub const ANALYZER: &str = "ljnljn.registry-installdate";
/// 单文件分析器名（plugin.toml 文件能力）。
pub const ANALYZER_FILE: &str = "ljnljn.registry-installdate.file";
/// 检材级分析器名（plugin.toml 检材能力）。
pub const ANALYZER_EVIDENCE: &str = "ljnljn.registry-installdate.evidence";
/// 插件 id（与 plugin.toml `id` 一致）。
/// 插件显示名（与 plugin.toml `name` 一致）。
pub const PLUGIN_ID: &str = "org.ljnljn.registry-installdate";
pub const PLUGIN_NAME: &str = "注册表 InstallDate 安装时间";
/// 单次宿主读取分块上限（SDK 上限 4 MiB，取 1 MiB 控制峰值）。
pub const READ_CHUNK: usize = 1024 * 1024;
/// 检材级分析里 hive 文件的大小上限（SOFTWARE 通常 100~400 MiB）。
pub const MAX_EVIDENCE_HIVE_BYTES: u64 = 2 * 1024 * 1024 * 1024;
/// 检材级兜底扫描时最多处理的同名候选数。
pub const MAX_FALLBACK_CANDIDATES: usize = 16;

// ---------------------------------------------------------------------------
// SDK 句柄 → ReadAt
// ---------------------------------------------------------------------------

/// 单文件句柄。
struct FileSource<'a> {
    file: &'a File,
}

impl ReadAt for FileSource<'_> {
    fn size(&self) -> u64 {
        self.file.size()
    }

    fn read_at(&self, offset: u64, length: usize) -> std::result::Result<Vec<u8>, String> {
        if length == 0 || offset >= self.file.size() {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(length.min(READ_CHUNK));
        let mut position = offset;
        let end = offset.saturating_add(length as u64).min(self.file.size());
        while position < end {
            let want = ((end - position) as usize).min(READ_CHUNK);
            let chunk = self
                .file
                .read(position, want)
                .map_err(|error| format!("file.read 失败@0x{position:x}: {error}"))?;
            if chunk.is_empty() {
                break;
            }
            position += chunk.len() as u64;
            out.extend_from_slice(&chunk);
        }
        if out.len() != length {
            return Err(format!(
                "短读: 0x{offset:x} 处需要 {length} 字节，实际 {} 字节",
                out.len()
            ));
        }
        Ok(out)
    }
}

/// 检材卷内路径。
struct VolumeSource<'a> {
    volume: &'a EvidenceVolume,
    path: String,
    size: u64,
}

impl ReadAt for VolumeSource<'_> {
    fn size(&self) -> u64 {
        self.size
    }

    fn read_at(&self, offset: u64, length: usize) -> std::result::Result<Vec<u8>, String> {
        if length == 0 || offset >= self.size {
            return Ok(Vec::new());
        }
        let want = (length as u64).min(self.size - offset);
        let bytes = self
            .volume
            .read(&self.path, offset, Some(want))
            .map_err(|error| format!("evidence.read 失败@0x{offset:x}: {error}"))?;
        if bytes.len() as u64 != want {
            return Err(format!(
                "短读: 期望 {want} 字节，实际 {} 字节",
                bytes.len()
            ));
        }
        Ok(bytes)
    }
}

// ---------------------------------------------------------------------------
// 单文件入口
// ---------------------------------------------------------------------------

/// 单文件句柄分析：读 regf 头 → 定位目标键 → 解释 InstallDate。
pub fn analyze_file_handle(file: &File) -> Result<AnalysisResult> {
    let source = FileSource { file };
    let report = analyze_hive(source, SourceInfo::file(file.name()));
    file.context().log(
        LogLevel::Info,
        &format!("{ANALYZER}: {} → {}", file.name(), report.summary),
    );
    Ok(render::build_result(&report))
}

/// 对一段内存字节做完整分析（测试与验证工具使用）。
pub fn analyze_bytes(bytes: &[u8], info: SourceInfo) -> HiveReport {
    analyze_hive(SliceReader::new(bytes), info)
}

// ---------------------------------------------------------------------------
// 检材级入口
// ---------------------------------------------------------------------------

/// 在卷内按层次（大小写不敏感）定位 `Windows/System32/config` 目录。
fn find_config_dir(volume: &EvidenceVolume) -> Option<String> {
    let mut windows_dirs = vec!["Windows".to_owned()];
    if let Ok(nodes) = volume.list("") {
        for node in nodes {
            if node.is_dir()
                && node.name.eq_ignore_ascii_case("Windows")
                && !windows_dirs.iter().any(|dir| dir.eq_ignore_ascii_case(&node.name))
            {
                windows_dirs.push(node.name);
            }
        }
    }
    for candidate in ["WinNT", "WINNT"] {
        if !windows_dirs.iter().any(|dir| dir == candidate) {
            windows_dirs.push(candidate.to_owned());
        }
    }
    for windows in windows_dirs {
        let system_dirs = if windows.eq_ignore_ascii_case("WinNT") {
            vec!["system32".to_owned()]
        } else {
            vec!["System32".to_owned(), "system32".to_owned()]
        };
        for system32 in system_dirs {
            let config = format!("{windows}/{system32}/config");
            if volume.is_dir(&config).unwrap_or(false) {
                return Some(config);
            }
        }
    }
    None
}

/// 在 `config` 目录里找名为 SOFTWARE 的文件（大小写不敏感），返回检材内相对路径。
fn find_config_file(volume: &EvidenceVolume, config_dir: &str, name: &str) -> Option<String> {
    let nodes = volume.list(config_dir).ok()?;
    nodes
        .into_iter()
        .find(|node| node.is_file() && !node.deleted && node.name.eq_ignore_ascii_case(name))
        .map(|node| format!("{config_dir}/{}", node.name))
}

/// 兜底：按名字扫描 `SOFTWARE` / `Software.hive` 等候选（config 目录不存在时使用）。
fn find_candidates(volume: &EvidenceVolume) -> Vec<String> {
    match volume.find_files_by_name(&["SOFTWARE", "Software", "SOFTWARE.hive"], &[], &[]) {
        Ok(mut paths) => {
            paths.sort();
            paths.truncate(MAX_FALLBACK_CANDIDATES);
            paths
        }
        Err(_) => Vec::new(),
    }
}

fn merge_reports(mut acc: HiveReport, next: HiveReport) -> HiveReport {
    acc.notes.extend(next.notes);
    acc.summary = format!("{}；{}", acc.summary, next.summary);
    acc
}

fn analyze_evidence_impl(evidence: &Evidence) -> Result<AnalysisResult> {
    let roots = evidence.roots()?;
    let mut reports: Vec<HiveReport> = Vec::new();
    let mut volume_notes: Vec<(String, String)> = Vec::new();
    for root in &roots {
        evidence.context().check_cancelled()?;
        let volume = evidence.volume(&root.root_id);
        let mut targets: Vec<String> = Vec::new();
        match find_config_dir(&volume) {
            Some(config) => match find_config_file(&volume, &config, "SOFTWARE") {
                Some(path) => targets.push(path),
                None => volume_notes.push((
                    root.root_id.clone(),
                    format!("{config} 下没有名为 SOFTWARE 的文件"),
                )),
            },
            None => volume_notes.push((
                root.root_id.clone(),
                "卷内没有 Windows/System32/config 目录，改用文件名扫描".to_owned(),
            )),
        }
        if targets.is_empty() {
            targets = find_candidates(&volume);
        }
        if targets.is_empty() {
            continue;
        }
        let mut used_header_name: Option<String> = None;
        for path in targets {
            evidence.context().check_cancelled()?;
            let Some(node) = volume.stat(&path)? else {
                volume_notes.push((root.root_id.clone(), format!("{path} 在列目录后消失，跳过")));
                continue;
            };
            if node.size > MAX_EVIDENCE_HIVE_BYTES {
                volume_notes.push((
                    root.root_id.clone(),
                    format!("{path} 有 {} 字节，超过解析上限，跳过", node.size),
                ));
                continue;
            }
            evidence.progress(
                reports.len() as u64,
                Some(roots.len() as u64),
                Some(&format!("解析 {} 的 {path}", root.root_id)),
            )?;
            let source = VolumeSource {
                volume: &volume,
                path: path.clone(),
                size: node.size,
            };
            let report = analyze_hive(source, SourceInfo::volume(&root.root_id, &path));
            if report.header_error.is_some() {
                // 头部就不过校验的文件不是可用 hive：不登记为检材结果，只记说明。
                volume_notes.push((
                    root.root_id.clone(),
                    format!("{path}：{}", report.summary),
                ));
                continue;
            }
            // 兜底扫描命中的非 config 副本：同名多卷时只保留第一份。
            if let Some(name) = &used_header_name {
                if reports
                    .iter()
                    .any(|existing| existing.header.file_name.as_deref() == Some(name.as_str()))
                {
                    continue;
                }
            }
            used_header_name = report.header.file_name.clone();
            reports.push(report);
        }
    }
    if reports.is_empty() {
        let detail = volume_notes
            .iter()
            .map(|(root, text)| format!("[{root}] {text}"))
            .collect::<Vec<_>>()
            .join("；");
        let mut report = analyze_hive(
            SliceReader::new(&[]),
            SourceInfo {
                label: "(未找到 hive)".to_owned(),
                kind: "volume",
                root: None,
            },
        );
        report.summary = format!(
            "在 {} 个可浏览卷里都没有找到 Windows/System32/config/SOFTWARE（{detail}）；请改用文件分析器选中已提取的 hive",
            roots.len()
        );
        report.header_error = None;
        return Ok(render::build_result(&report));
    }
    let mut merged = reports.remove(0);
    for report in reports {
        merged = merge_reports(merged, report);
    }
    for (root, text) in volume_notes {
        merged
            .notes
            .push(crate::extract::ReportNote::info("coverage", format!("[{root}] {text}")));
    }
    Ok(render::build_result(&merged))
}

// ---------------------------------------------------------------------------
// SDK 入口
// ---------------------------------------------------------------------------

struct RegistryInstallDate;

/// 单文件入口：与检材入口分开命名，避免宿主把两个能力当成重复 analyzer。
pub struct FileEntry;
/// 检材级入口。
pub struct EvidenceEntry;

impl FileAnalyzer for FileEntry {
    fn analyzer(&self) -> &str {
        ANALYZER_FILE
    }

    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        analyze_file_handle(file)
    }
}

impl EvidenceAnalyzer for EvidenceEntry {
    fn analyzer(&self) -> &str {
        ANALYZER_EVIDENCE
    }

    fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult> {
        analyze_evidence_impl(evidence)
    }
}

/// `plugin.toml` 的 id/version 与代码注册值是否一致（测试使用）。
pub fn identity_matches(plugin_id: &str, version: &str) -> bool {
    plugin_id == PLUGIN_ID && version == env!("CARGO_PKG_VERSION")
}

/// 由宿主调用的插件构造函数。身份、版本与 plugin.toml 必须一致。
fn build_plugin() -> Plugin {
    Plugin::new(PLUGIN_ID, PLUGIN_NAME, env!("CARGO_PKG_VERSION"))
        .file_analyzer(FileEntry)
        .evidence_analyzer(EvidenceEntry)
}

export_plugin!(build_plugin);

/// 从 artifact 属性取文本（测试与工具辅助）。
pub fn attr_text(artifact: &lovelycarve_plugin::Artifact, key: &str) -> Option<String> {
    match artifact.attributes.get(key) {
        Some(Value::String(text)) => text.as_str().map(str::to_owned),
        Some(Value::Boolean(flag)) => Some(flag.to_string()),
        Some(Value::Integer(number)) => number
            .as_u64()
            .map(|value| value.to_string())
            .or_else(|| number.as_i64().map(|value| value.to_string())),
        _ => None,
    }
}