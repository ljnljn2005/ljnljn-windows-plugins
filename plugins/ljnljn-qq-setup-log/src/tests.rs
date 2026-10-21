use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use lovelycarve_plugin::testing::{Fixture, Harness, TestRun};

const FULL_FLOW: &str = concat!(
    "0831/180025 [Setup] 开始安装 合成样本\r\n",
    "0831/180026 [Install] 正在安装 组件 Core\r\n",
    "0831/180708 [Complete] 安装完成 Success\r\n",
    "0831/180708 Show QQ Window\r\n",
    "0831/180709 [Launch] launch app.exe\r\n",
);

const MISSING_COMPLETE: &str = concat!(
    "0912/101500 Setup begin\r\n",
    "0912/101659 Install files copied\r\n",
    "0912/101700 Show QQ Window\r\n",
    "0912/101701 show qq window again\r\n",
    "startup finished without marker\r\n",
);

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
            "ljnljn-qq-setup-{label}-{}-{unique}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let file = self.path.join(name);
        fs::write(&file, bytes).unwrap();
        file
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
        .run("qq_setup_log", Fixture::files(&[path]))
        .expect("file run")
}

#[test]
fn full_flow_keeps_line_numbers_categories_and_sources() {
    let fixture = FixtureDir::new("full");
    let path = fixture.write("qq_setup.log", FULL_FLOW.as_bytes());
    let run = run_file(&path);

    assert_eq!(run.count("qqsetup.file"), 1);
    let file = run.of_type("qqsetup.file")[0];
    assert_eq!(file.text("source_file"), Some("qq_setup.log"));
    assert_eq!(file.text("encoding"), Some("utf_8"));
    assert_eq!(file.int("line_count"), Some(5));
    assert_eq!(file.int("event_count"), Some(5));
    assert_eq!(file.int("unparsed_line_count"), Some(0));
    assert_eq!(file.int("blank_line_count"), Some(0));

    assert_eq!(run.count("qqsetup.event"), 5);
    let events = run.of_type("qqsetup.event");
    let expected = [
        (1, "0831/180025", "install"),
        (2, "0831/180026", "install"),
        (3, "0831/180708", "complete"),
        (4, "0831/180708", "launch"),
        (5, "0831/180709", "launch"),
    ];
    for (event, (line_no, time_raw, category)) in events.iter().zip(expected) {
        assert_eq!(event.int("line_no"), Some(line_no));
        assert_eq!(event.text("time_raw"), Some(time_raw));
        assert_eq!(event.text("category"), Some(category));
        assert_eq!(event.int("char_offset"), Some(0));
        assert_eq!(event.int("month"), Some(8));
        assert_eq!(event.int("day"), Some(31));
    }
    // The fourth line is "Show QQ Window": launch only, no complete marker.
    let hits = events[3]
        .get("category_hits")
        .expect("category hits")
        .as_array()
        .unwrap();
    assert_eq!(hits.len(), 1);
    assert_eq!(hits[0].as_str(), Some("launch"));

    assert_eq!(events[2].sources.len(), 1);
    assert_eq!(events[2].sources[0].note.as_deref(), Some("line 3"));
    assert_eq!(events[2].sources[0].root.as_deref(), Some("files"));
    assert_eq!(events[0].int("hour"), Some(18));
    assert_eq!(events[0].int("minute"), Some(0));
    assert_eq!(events[0].int("second"), Some(25));
}

#[test]
fn missing_complete_marker_does_not_invent_an_event() {
    let fixture = FixtureDir::new("missing");
    let path = fixture.write("qq_setup.log", MISSING_COMPLETE.as_bytes());
    let run = run_file(&path);

    assert_eq!(run.count("qqsetup.event"), 4);
    assert!(run
        .of_type("qqsetup.event")
        .iter()
        .all(|event| event.text("category") != Some("complete")));
    let file = run.of_type("qqsetup.file")[0];
    assert_eq!(file.int("unparsed_line_count"), Some(1));
    let limitations = file
        .get("limitations")
        .expect("limitations")
        .as_array()
        .unwrap();
    assert!(limitations.iter().any(|item| item
        .as_str()
        .is_some_and(|text| text.contains("1 行无时间戳"))));
}

#[test]
fn gbk_log_is_decoded_and_classified() {
    let fixture = FixtureDir::new("gbk");
    let (bytes, _, unmappable) =
        encoding_rs::GBK.encode("0831/180025 开始安装\r\n0831/180708 安装完成\r\n");
    assert!(!unmappable);
    let path = fixture.write("qq_setup.log", bytes.as_ref());
    let run = run_file(&path);

    let file = run.of_type("qqsetup.file")[0];
    assert_eq!(file.text("encoding"), Some("gbk"));
    let events = run.of_type("qqsetup.event");
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].text("category"), Some("install"));
    assert_eq!(events[1].text("category"), Some("complete"));
    assert!(events[1].text("line_text").unwrap().contains("安装完成"));
}

#[test]
fn lossy_decoding_is_reported_as_a_warning() {
    let fixture = FixtureDir::new("lossy");
    let path = fixture.write(
        "qq_setup.log",
        b"0831/180025 setup\n\xff\xfe\xff\n0831/180708 complete\n",
    );
    let run = run_file(&path);

    let file = run.of_type("qqsetup.file")[0];
    assert_eq!(file.text("encoding"), Some("utf_8_lossy"));
    assert_eq!(run.count("qqsetup.event"), 2);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "LOSSY_DECODING"));
}

#[test]
fn more_than_9999_events_is_a_per_file_resource_limit() {
    let fixture = FixtureDir::new("toomany");
    let path = fixture.write(
        "qq_setup.log",
        "0101/000000 other\n".repeat(10_000).as_bytes(),
    );
    let run = run_file(&path);

    assert_eq!(run.count("qqsetup.file"), 0);
    assert_eq!(run.count("qqsetup.event"), 0);
    assert!(
        run.warnings
            .iter()
            .any(|(code, message, _)| code == "RESOURCE_LIMIT"
                && message.contains("10000 条时间事件"))
    );
}

#[test]
fn marker_only_line_is_counted_unparsed_not_an_event() {
    let fixture = FixtureDir::new("marker");
    let path = fixture.write("qq_setup.log", b"setup\r\n0831/180025 working\r\n");
    let run = run_file(&path);

    assert_eq!(run.count("qqsetup.file"), 1);
    assert_eq!(run.count("qqsetup.event"), 1);
    let event = run.of_type("qqsetup.event")[0];
    assert_eq!(event.int("line_no"), Some(2));
    assert_eq!(event.text("category"), Some("other"));
    let file = run.of_type("qqsetup.file")[0];
    assert_eq!(file.int("unparsed_line_count"), Some(1));
}

#[test]
fn oversized_log_is_rejected_with_a_resource_limit_warning() {
    let fixture = FixtureDir::new("oversized");
    let path = fixture.write(
        "qq_setup.log",
        &vec![b'a'; super::parser::MAX_INPUT_BYTES + 1],
    );
    let run = run_file(&path);

    assert_eq!(run.count("qqsetup.file"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "RESOURCE_LIMIT"));
}

#[test]
fn empty_log_is_a_typed_zero_event_summary() {
    let fixture = FixtureDir::new("empty");
    let path = fixture.write("qq_setup.log", b"");
    let run = run_file(&path);

    assert_eq!(run.count("qqsetup.file"), 1);
    assert_eq!(run.count("qqsetup.event"), 0);
    let file = run.of_type("qqsetup.file")[0];
    assert_eq!(file.int("line_count"), Some(0));
    let limitations = file
        .get("limitations")
        .expect("limitations")
        .as_array()
        .unwrap();
    assert!(limitations
        .iter()
        .any(|item| item.as_str().is_some_and(|text| text.contains("输入为空"))));
}

#[test]
fn empty_file_selection_returns_an_explicit_warning() {
    let run = harness()
        .run("qq_setup_log", Fixture::files(&[]))
        .expect("file run");

    assert_eq!(run.count("qqsetup.file"), 0);
    assert!(run
        .warnings
        .iter()
        .any(|(code, _, _)| code == "INPUT_NOT_FOUND"));
}
