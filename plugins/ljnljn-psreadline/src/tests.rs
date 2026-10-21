use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRun};

const HISTORY: &str = "Get-Date\ncurl https://a.example/x https://a.example/x https://b.example/?q=a%20b\ncurl https://a.example/x\n";

struct FixtureDir {
    path: PathBuf,
}

impl FixtureDir {
    fn new(label: &str) -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "ljnljn-psreadline-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, relative: &str, bytes: &[u8]) -> PathBuf {
        let file = self.path.join(relative);
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, bytes).unwrap();
        file
    }

    fn directory(&self, relative: &str) -> PathBuf {
        let directory = self.path.join(relative);
        fs::create_dir_all(&directory).unwrap();
        directory
    }
}

impl Drop for FixtureDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn harness() -> Harness {
    Harness::new(super::plugin)
}

fn run_file(path: &Path) -> TestRun {
    harness()
        .run("psreadline_files", Fixture::files(&[path]))
        .expect("file run")
}

fn run_evidence(volume: &Path) -> TestRun {
    harness()
        .run(
            "psreadline_evidence",
            Fixture::evidence(&[("part:1", volume)]),
        )
        .expect("evidence run")
}

#[test]
fn file_analyzer_counts_logical_commands_and_emits_urls() {
    let fixture = FixtureDir::new("file");
    let path = fixture.write("ConsoleHost_history.txt", HISTORY.as_bytes());
    let run = run_file(&path);

    assert_eq!(run.count("psreadline.history"), 1);
    let history = run.of_type("psreadline.history")[0];
    assert_eq!(history.text("source_file"), Some("ConsoleHost_history.txt"));
    assert_eq!(history.int("command_count"), Some(3));
    assert_eq!(history.int("url_command_count"), Some(2));

    assert_eq!(run.count("psreadline.command"), 2);
    let commands = run.of_type("psreadline.command");
    assert_eq!(commands[0].int("index"), Some(2));
    assert_eq!(commands[0].int("line"), Some(2));
    assert_eq!(
        commands[0].text("command"),
        Some("curl https://a.example/x https://a.example/x https://b.example/?q=a%20b")
    );
    let urls = commands[0].get("urls").expect("urls").as_array().unwrap();
    assert_eq!(urls.len(), 2);
    assert_eq!(urls[0].as_str(), Some("https://a.example/x"));
    assert_eq!(urls[1].as_str(), Some("https://b.example/?q=a%20b"));
    assert_eq!(commands[1].int("index"), Some(3));

    assert_eq!(commands[0].sources.len(), 1);
    assert_eq!(commands[0].sources[0].note.as_deref(), Some("line 2"));
    assert_eq!(commands[1].sources[0].note.as_deref(), Some("line 3"));
}

#[test]
fn invalid_history_is_a_warning_not_an_empty_success() {
    let fixture = FixtureDir::new("invalid");
    let path = fixture.write("ConsoleHost_history.txt", &[0xff]);
    let run = run_file(&path);

    assert_eq!(run.count("psreadline.history"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INVALID_HISTORY"));
    assert!(run.summary.as_deref().unwrap_or("").contains("无法解析 1"));
}

#[test]
fn oversized_history_is_rejected_with_a_resource_limit_warning() {
    let fixture = FixtureDir::new("oversized");
    let path = fixture.write(
        "ConsoleHost_history.txt",
        &vec![b'a'; super::parser::MAX_BYTES + 1],
    );
    let run = run_file(&path);

    assert_eq!(run.count("psreadline.history"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "RESOURCE_LIMIT"));
}

#[test]
fn empty_file_selection_returns_an_explicit_warning() {
    let run = harness()
        .run("psreadline_files", Fixture::files(&[]))
        .expect("file run");

    assert_eq!(run.count("psreadline.history"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}

#[test]
fn evidence_analyzer_scans_standard_user_profiles() {
    let fixture = FixtureDir::new("evidence");
    fixture.write(
        "volume/Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
        HISTORY.as_bytes(),
    );
    let volume = fixture.directory("volume");
    let run = run_evidence(&volume);

    assert_eq!(run.count("psreadline.history"), 1);
    let history = run.of_type("psreadline.history")[0];
    assert_eq!(
        history.text("source_file"),
        Some("part:1/Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt")
    );
    assert_eq!(history.int("command_count"), Some(3));
    assert_eq!(history.int("url_command_count"), Some(2));
    assert_eq!(history.sources[0].root.as_deref(), Some("part:1"));
    assert_eq!(
        history.sources[0].path.as_deref(),
        Some("Users/alice/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt")
    );

    assert_eq!(run.count("psreadline.command"), 2);
    assert_eq!(run.count("psreadline.total"), 1);
    let total = run.of_type("psreadline.total")[0];
    assert_eq!(total.int("file_count"), Some(1));
    assert_eq!(total.int("url_command_count"), Some(2));
}

#[test]
fn evidence_analyzer_warns_when_no_standard_history_exists() {
    let fixture = FixtureDir::new("missing");
    fixture.directory("volume/Users/bob/Documents");
    let volume = fixture.directory("volume");
    let run = run_evidence(&volume);

    assert_eq!(run.count("psreadline.history"), 0);
    assert_eq!(run.count("psreadline.total"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "HISTORY_NOT_FOUND"));
}
