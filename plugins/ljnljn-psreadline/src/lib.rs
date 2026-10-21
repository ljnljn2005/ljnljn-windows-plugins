mod parser;

use lovelycarve_plugin::{
    AnalysisResult, Artifact, Attributes, Error, Evidence, EvidenceAnalyzer,
    File, FileAnalyzer, Plugin, Result, ResultColumn, ResultNode, Value,
};

const ID: &str = "org.ljnljn.psreadline";
const NAME: &str = "PowerShell历史URL";
const SUBITEM: &str = "PowerShell历史URL";
const RELATIVE: [&str; 2] = [
    "AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
    "AppData/Roaming/Microsoft/PowerShell/PSReadLine/ConsoleHost_history.txt",
];

struct Analyzer;

fn result() -> AnalysisResult {
    AnalysisResult {
        nodes: vec![
            ResultNode {
                node_type: "psreadline.total".into(),
                name: "全部历史统计".into(),
                columns: [
                    ("psreadline.file_count", "历史文件数"),
                    ("psreadline.url_command_count", "含URL命令总数"),
                ].into_iter().map(|(key, label)| ResultColumn { key: key.into(), label: label.into() }).collect(),
            },
            ResultNode {
                node_type: "psreadline.history".into(),
                name: "历史文件统计".into(),
                columns: [
                    ("source.path", "来源文件"),
                    ("psreadline.command_count", "命令数"),
                    ("psreadline.url_command_count", "含URL命令数"),
                ].into_iter().map(|(key, label)| ResultColumn { key: key.into(), label: label.into() }).collect(),
            },
            ResultNode {
                node_type: "psreadline.command".into(),
                name: "含URL的命令".into(),
                columns: [
                    ("source.path", "来源文件"),
                    ("psreadline.line", "起始行"),
                    ("psreadline.command", "历史命令"),
                    ("ljnljn.psreadline.urls", "URL"),
                ].into_iter().map(|(key, label)| ResultColumn { key: key.into(), label: label.into() }).collect(),
            },
        ],
        ..AnalysisResult::default()
    }
}

fn append(out: &mut AnalysisResult, bytes: &[u8], source: &Attributes) -> Result<usize> {
    let history = parser::parse(bytes).map_err(|e| Error::new("INVALID_HISTORY", e))?;
    if out.artifacts.len() + history.matches.len() + 1 > 9000 {
        return Err(Error::new("RESOURCE_LIMIT", "combined results exceed 9000 items; no partial total returned"));
    }
    let count = history.matches.len();
    let mut attributes = source.clone();
    attributes.insert("psreadline.command_count", history.commands as u64);
    attributes.insert("psreadline.url_command_count", count as u64);
    attributes.insert("psreadline.count_basis", "nonblank logical commands; multiline continuation joined; repeated commands counted separately");
    attributes.insert("psreadline.limitations", "literal HTTP/HTTPS addresses only; not proof that a request ran or succeeded; history contains no reliable execution timestamps");
    out.artifacts.push(Artifact {
        artifact_type: "psreadline.history".into(),
        title: "PowerShell历史统计".into(),
        value: Some((count as u64).into()), attributes,
    });
    for command in history.matches {
        let mut attributes = source.clone();
        attributes.insert("psreadline.index", command.index as u64);
        attributes.insert("psreadline.line", command.line as u64);
        attributes.insert("psreadline.command", command.text.clone());
        attributes.insert("ljnljn.psreadline.urls", Value::Array(command.urls.into_iter().map(Value::from).collect()));
        out.artifacts.push(Artifact {
            artifact_type: "psreadline.command".into(),
            title: format!("历史命令 #{}", command.index),
            value: Some(command.text.into()), attributes,
        });
    }
    if lovelycarve_plugin::value::encode(&out.to_value())?.len() > 7 * 1024 * 1024 - 8192 {
        return Err(Error::new("RESOURCE_LIMIT", "encoded history results exceed 7 MiB; no partial count returned"));
    }
    Ok(count)
}

impl FileAnalyzer for Analyzer {
    fn analyzer(&self) -> &str { "ljnljn.psreadline.urls.file" }
    fn analyze(&self, file: &File) -> Result<AnalysisResult> {
        file.context().check_cancelled()?;
        if file.size() > parser::MAX_BYTES as u64 {
            return Err(Error::new("RESOURCE_LIMIT", "history exceeds 4 MiB"));
        }
        let bytes = file.read(0, file.size() as usize)?;
        if bytes.len() as u64 != file.size() {
            return Err(Error::new("SHORT_READ", "history file was not read completely"));
        }
        let source: Attributes = [
            ("source.path", file.name()),
            ("source.file_id", file.id()),
        ].into_iter().collect();
        let mut out = result();
        let count = append(&mut out, &bytes, &source)?;
        file.context().check_cancelled()?;
        out.summary = Some(format!("找到 {count} 条含HTTP/HTTPS地址的历史命令；仅表示命令被保存，不证明已执行或请求成功。"));
        Ok(out)
    }
}

impl EvidenceAnalyzer for Analyzer {
    fn analyzer(&self) -> &str { "ljnljn.psreadline.urls" }
    fn analyze_evidence(&self, evidence: &Evidence) -> Result<AnalysisResult> {
        let mut out = result();
        if !evidence.wants(SUBITEM) {
            out.summary = Some("未选择PowerShell历史URL子项。".into());
            return Ok(out);
        }
        let mut files = 0;
        let mut count = 0;
        for root in evidence.roots()? {
            let volume = evidence.volume(&root.root_id);
            let mut profiles = vec![String::new()];
            if volume.is_dir("Users")? {
                let users = volume.list("Users")?;
                if users.len() > 512 {
                    return Err(Error::new("RESOURCE_LIMIT", "Users directory exceeds 512 entries"));
                }
                for user in users.into_iter().filter(|n| n.is_dir() && !n.deleted) {
                    if user.name.contains(['/', '\\']) || matches!(user.name.as_str(), "." | "..") {
                        return Err(Error::new("INVALID_PATH", "unsafe user directory component"));
                    }
                    profiles.push(format!("Users/{}", user.name));
                }
            }
            for profile in profiles {
                for relative in RELATIVE {
                    evidence.context().check_cancelled()?;
                    let path = if profile.is_empty() { relative.into() } else { format!("{profile}/{relative}") };
                    let Some(node) = volume.stat(&path)? else { continue };
                    if !node.is_file() || node.deleted { continue; }
                    if node.size > parser::MAX_BYTES as u64 {
                        return Err(Error::new("RESOURCE_LIMIT", format!("history exceeds 4 MiB: {path}")));
                    }
                    let bytes = volume.read(&path, 0, Some(node.size))?;
                    if bytes.len() as u64 != node.size { return Err(Error::new("SHORT_READ", path)); }
                    let mut source: Attributes = [
                        ("source.path", path.as_str()),
                        ("source.root", root.root_id.as_str()),
                        ("source.evidence_id", evidence.id()),
                    ].into_iter().collect();
                    source.insert("source.scope", "standard Users and profile-root Windows PowerShell/PowerShell PSReadLine paths");
                    count += append(&mut out, &bytes, &source)?;
                    files += 1;
                }
            }
        }
        if files == 0 { return Err(Error::not_found("No ConsoleHost_history.txt in standard Windows user-profile paths; select an exported history file with the file analyzer")); }
        let attributes: Attributes = [
            ("source.evidence_id", Value::from(evidence.id())),
            ("psreadline.file_count", Value::from(files as u64)),
            ("psreadline.url_command_count", Value::from(count as u64)),
            ("psreadline.count_basis", Value::from("sum of per-file logical commands; repeated and cross-profile commands are not deduplicated")),
        ].into_iter().collect();
        out.artifacts.push(Artifact {
            artifact_type: "psreadline.total".into(),
            title: "全部已读取历史文件的含URL命令总数".into(),
            value: Some((count as u64).into()), attributes,
        });
        out.summary = Some(format!("读取 {files} 份PSReadLine历史，共 {count} 条含URL的命令。自定义HistorySavePath、其他host历史文件及已删除历史不在自动扫描范围；不推断执行时间。"));
        Ok(out)
    }
}

fn plugin() -> Plugin {
    Plugin::new(ID, NAME, "0.1.0").file_analyzer(Analyzer).evidence_analyzer(Analyzer)
}

lovelycarve_plugin::export_plugin!(plugin);
