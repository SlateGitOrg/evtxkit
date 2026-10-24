//! End-to-end tests of the `evtxkit` binary.
#![allow(clippy::unwrap_used)]

mod common;

use serde_json::Value as Json;
use std::io::{BufRead, BufReader, Read};
use std::process::{Command, Output, Stdio};

fn evtxkit(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evtxkit"))
        .args(args)
        .env_remove("RUST_LOG")
        .output()
        .unwrap()
}

fn sample(name: &str) -> String {
    common::sample(name).to_string_lossy().into_owned()
}

fn stdout(o: &Output) -> String {
    String::from_utf8(o.stdout.clone()).unwrap()
}

fn json_lines(o: &Output) -> Vec<Json> {
    stdout(o)
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

#[test]
fn dump_jsonl_is_one_valid_object_per_record() {
    let o = evtxkit(&["dump", &sample("security.evtx")]);
    assert!(o.status.success());
    let lines = json_lines(&o);
    assert_eq!(lines.len(), 2261);
    let ids: Vec<u64> = lines
        .iter()
        .map(|l| l["record_id"].as_u64().unwrap())
        .collect();
    assert!(
        ids.windows(2).all(|w| w[0] < w[1]),
        "ids ascend in file order"
    );
    assert_eq!(lines[1]["event"]["System"]["EventID"], 4624);
    assert_eq!(lines[1]["event"]["EventData"]["TargetUserName"], "SYSTEM");
}

#[test]
fn thread_count_does_not_change_output() {
    let one = evtxkit(&["dump", "-t", "1", &sample("system.evtx")]);
    let many = evtxkit(&["dump", "-t", "6", &sample("system.evtx")]);
    assert_eq!(one.stdout, many.stdout);
    assert_eq!(stdout(&one).lines().count(), 1881);
}

#[test]
fn dump_xml_and_fields_formats() {
    let o = evtxkit(&["dump", "-f", "xml", &sample("new-user-security.evtx")]);
    let xml = stdout(&o);
    assert_eq!(xml.matches("<?xml version=").count(), 4);
    assert!(xml.contains("<EventID>4728</EventID>"));

    let o = evtxkit(&[
        "dump",
        "-f",
        "fields",
        "--sigma",
        "-t",
        "2",
        &sample("sysmon.evtx"),
    ]);
    let lines = json_lines(&o);
    assert_eq!(lines.len(), 358);
    let first = &lines[0];
    assert_eq!(first["_logsource"]["category"], "process_creation");
    assert_eq!(first["_logsource"]["service"], "sysmon");
    assert_eq!(first["fields"]["Image"], "C:\\Windows\\SysWOW64\\PING.EXE");
}

#[test]
fn dump_filters_errors_and_output_file() {
    let o = evtxkit(&[
        "dump",
        "-w",
        "EventID=4624",
        "-w",
        "LogonType=5",
        &sample("security.evtx"),
    ]);
    let lines = json_lines(&o);
    assert!(!lines.is_empty());
    assert!(
        lines
            .iter()
            .all(|l| l["event"]["EventData"]["LogonType"] == 5)
    );

    let o = evtxkit(&[
        "dump",
        "--emit-errors",
        &sample("sample_with_a_bad_chunk_magic.evtx"),
    ]);
    let lines = json_lines(&o);
    let errors = lines.iter().filter(|l| l["error"] == true).count();
    assert_eq!(errors, 3, "two corrupt slots and one framing error");
    assert_eq!(lines.len() - errors, 301);
    let log = String::from_utf8_lossy(&o.stderr);
    assert!(log.contains("bad chunk signature"), "{log}");

    let dir = std::env::temp_dir().join(format!("evtxkit-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("out.jsonl");
    let o = evtxkit(&[
        "dump",
        "-q",
        "-o",
        path.to_str().unwrap(),
        &sample("new-user-security.evtx"),
    ]);
    assert!(o.status.success() && o.stdout.is_empty());
    assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 4);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The fix-round-1 review case end to end: a 68 KB file whose one record
/// asked for ~25 million elements is reported as one record error.
#[test]
fn hostile_expansion_is_a_record_error() {
    let dir = std::env::temp_dir().join(format!("evtxkit-bomb-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("bomb.evtx");
    let data = common::builder::file(&[common::hostile::array_clone_bomb(500)]);
    assert_eq!(data.len(), 69_632);
    std::fs::write(&path, data).unwrap();
    let o = evtxkit(&["dump", "-t", "1", "--emit-errors", path.to_str().unwrap()]);
    assert!(o.status.success());
    let lines = json_lines(&o);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0]["error"], true);
    assert_eq!(
        lines[0]["message"],
        "node budget exceeded: more than 100000 nodes per record"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn strict_crc_skips_damaged_chunks() {
    let lenient = evtxkit(&[
        "stats",
        "--json",
        &sample("sample_with_a_bad_chunk_magic.evtx"),
    ]);
    let strict = evtxkit(&[
        "stats",
        "--json",
        "--strict-crc",
        &sample("sample_with_a_bad_chunk_magic.evtx"),
    ]);
    let l: Json = serde_json::from_slice(&lenient.stdout).unwrap();
    let s: Json = serde_json::from_slice(&strict.stdout).unwrap();
    assert_eq!(l["total"]["records"], 301);
    assert_eq!(s["total"]["skipped_chunks"], 3);
    assert!(s["total"]["records"].as_u64().unwrap() < 301);
}

#[test]
fn stats_json_and_text() {
    let o = evtxkit(&[
        "stats",
        "--json",
        "--chunks",
        "--by",
        "TargetUserName",
        &sample("security.evtx"),
    ]);
    assert!(o.status.success());
    let v: Json = serde_json::from_slice(&o.stdout).unwrap();
    let f = &v["files"][0];
    assert_eq!(f["records"], 2261);
    assert_eq!(f["chunks"], 26);
    assert_eq!(f["empty_slots"], 7);
    assert_eq!(f["crc"]["header_mismatches"], 0);
    assert_eq!(f["chunk_slots"].as_array().unwrap().len(), 33);
    assert_eq!(f["group_by"]["field"], "TargetUserName");
    assert_eq!(f["format_version"], "3.1");

    // sysmon.evtx: the header claims 1 chunk; 9 decode, the 8 slots after
    // them hold stale non-chunk bytes and are reported as slack, not damage.
    let o = evtxkit(&["stats", "--json", &sample("sysmon.evtx")]);
    let v: Json = serde_json::from_slice(&o.stdout).unwrap();
    assert_eq!(v["total"]["chunks"], 9);
    assert_eq!(v["total"]["slack_slots"], 8);
    assert_eq!(v["total"]["corrupt_slots"], 0);
    assert!(
        o.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );

    let o = evtxkit(&[
        "stats",
        "--chunks",
        "--top",
        "3",
        &sample("Application_no_crc32.evtx"),
        &sample("system.evtx"),
    ]);
    let text = stdout(&o);
    assert!(text.contains("slot  kind"), "{text}");
    assert!(text.contains("disabled"));
    assert!(text.contains("\ntotal\n"));
    assert!(text.contains("records    1898 decoded"), "{text}");
}

#[test]
fn grep_text_fields_and_logsource() {
    let o = evtxkit(&["grep", "-c", "-w", "EventID=4624", &sample("security.evtx")]);
    assert!(o.status.success());
    let n: u64 = stdout(&o).trim().parse().unwrap();
    assert!(n > 100);

    let o = evtxkit(&[
        "grep",
        "-c",
        "--category",
        "process_creation",
        &sample("sysmon.evtx"),
    ]);
    assert_eq!(stdout(&o).trim(), "227");

    let o = evtxkit(&[
        "grep",
        "--sigma",
        "-f",
        "fields",
        "-w",
        "Image|endswith=\\ping.exe",
        "-e",
        "127.0.0.1",
        &sample("sysmon.evtx"),
    ]);
    let lines = json_lines(&o);
    assert!(!lines.is_empty());
    assert!(lines.iter().all(|l| {
        l["fields"]["CommandLine"]
            .as_str()
            .unwrap()
            .contains("127.0.0.1")
    }));

    let o = evtxkit(&[
        "grep",
        "-c",
        "--service",
        "security",
        &sample("security.evtx"),
    ]);
    assert_eq!(stdout(&o).trim(), "2261");

    let o = evtxkit(&[
        "grep",
        "-e",
        "no-such-text-anywhere",
        &sample("new-user-security.evtx"),
    ]);
    assert_eq!(
        o.status.code(),
        Some(1),
        "grep exits 1 when nothing matches"
    );
}

#[test]
fn custom_mapping_file() {
    let dir = std::env::temp_dir().join(format!("evtxkit-map-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let map = dir.join("m.yml");
    std::fs::write(
        &map,
        "name: test\ncategories:\n  - {category: user_added_to_group, channel: Security, event_ids: [4728], rename: {MemberSid: Member}}\n",
    )
    .unwrap();
    let o = evtxkit(&[
        "grep",
        "--mapping",
        map.to_str().unwrap(),
        "--category",
        "user_added_to_group",
        "-f",
        "fields",
        &sample("new-user-security.evtx"),
    ]);
    let lines = json_lines(&o);
    assert_eq!(lines.len(), 1);
    assert!(
        lines[0]["fields"]["Member"]
            .as_str()
            .unwrap()
            .starts_with("S-1-5-21-")
    );
    std::fs::write(&map, "name: [").unwrap();
    let o = evtxkit(&[
        "dump",
        "--mapping",
        map.to_str().unwrap(),
        &sample("new-user-security.evtx"),
    ]);
    assert_eq!(o.status.code(), Some(2));
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn usage_errors_exit_2() {
    let cases: Vec<Vec<String>> = vec![
        vec!["grep".into(), sample("security.evtx")],
        vec!["dump".into(), "/nonexistent/file.evtx".into()],
        vec![
            "dump".into(),
            "-w".into(),
            "Broken".into(),
            sample("security.evtx"),
        ],
        vec![
            "dump".into(),
            common::sample("../golden.rs")
                .to_string_lossy()
                .into_owned(),
        ],
    ];
    for args in cases {
        let refs: Vec<&str> = args.iter().map(String::as_str).collect();
        let o = evtxkit(&refs);
        assert_eq!(
            o.status.code(),
            Some(2),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(String::from_utf8_lossy(&o.stderr).starts_with("evtxkit: "));
    }
}

#[test]
fn closed_stdout_is_not_an_error() {
    let mut child = Command::new(env!("CARGO_BIN_EXE_evtxkit"))
        .args([
            "dump",
            "-t",
            "2",
            &sample("security.evtx"),
            &sample("system.evtx"),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut first = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut first)
        .unwrap();
    assert!(first.starts_with("{\"record_id\":1,"));
    let status = child.wait().unwrap();
    let mut err = String::new();
    child
        .stderr
        .take()
        .unwrap()
        .read_to_string(&mut err)
        .unwrap();
    assert!(status.success(), "status {status:?}, stderr {err}");
}

#[test]
fn verbose_logging_reports_progress() {
    let o = evtxkit(&["-v", "stats", &sample("HelloForBusiness-Operational.evtx")]);
    let log = String::from_utf8_lossy(&o.stderr);
    assert!(log.contains("done"), "{log}");
    assert!(log.contains("record-data CRC32 mismatch"), "{log}");
    let o = evtxkit(&["-vv", "stats", &sample("HelloForBusiness-Operational.evtx")]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("size copy mismatch"));
}
