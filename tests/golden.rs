//! Golden tests: evtxkit must reproduce the reference parser's output.
//!
//! `tests/golden/<sample>.jsonl.gz` was produced by `scripts/gen-golden.sh`,
//! which runs the `evtx` crate (pinned in tools/refdump) over each sample and
//! records every record as a canonical tree. The comparison is semantic
//! (element names, attribute order and values, text) rather than textual, so
//! it is independent of indentation or escaping style.
#![allow(clippy::unwrap_used)]

mod common;

use evtxkit::EvtxFile;
use flate2::read::GzDecoder;
use serde_json::Value as Json;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;

struct Golden {
    records: Vec<(u64, i128, Json)>,
}

fn load_golden(name: &str) -> Golden {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden")
        .join(format!("{name}.jsonl.gz"));
    let file = std::fs::File::open(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut records = Vec::new();
    for line in BufReader::new(GzDecoder::new(file)).lines() {
        let v: Json = serde_json::from_str(&line.unwrap()).unwrap();
        if v.get("error").is_some() {
            continue;
        }
        let ts: i128 = v["timestamp_ns"].as_str().unwrap().parse().unwrap();
        records.push((v["record_id"].as_u64().unwrap(), ts, v["tree"].clone()));
    }
    Golden { records }
}

fn check_sample(name: &str) -> (usize, usize) {
    let golden = load_golden(name);
    let file = EvtxFile::open(common::sample(&format!("{name}.evtx"))).unwrap();
    let mut ours = Vec::new();
    let mut our_errors = Vec::new();
    let mut recovered = 0;
    for r in file.records() {
        match r {
            // Records found by resynchronising after a framing error are extra
            // relative to the reference, which abandons the rest of such chunks.
            Ok(r) if r.recovered => recovered += 1,
            Ok(r) => ours.push((
                r.record_id,
                r.timestamp.unix_nanos(),
                common::canonical(&r.root),
            )),
            Err(e) => our_errors.push(e.to_string()),
        }
    }
    let mut mismatches = Vec::new();
    for (i, (want, got)) in golden.records.iter().zip(&ours).enumerate() {
        if want != got {
            mismatches.push(format!(
                "#{i} record {}:\n  want {}\n  got  {}",
                want.0, want.2, got.2
            ));
        }
    }
    assert!(
        mismatches.is_empty() && golden.records.len() == ours.len(),
        "{name}: {} reference records vs {} ours, {} mismatches; our errors: {our_errors:?}\n{}",
        golden.records.len(),
        ours.len(),
        mismatches.len(),
        mismatches
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
    (ours.len(), recovered)
}

macro_rules! golden {
    ($($test:ident => $name:literal),* $(,)?) => {
        $(#[test] fn $test() { check_sample($name); })*

        #[test]
        fn recovery_only_happens_in_the_damaged_sample() {
            $(
                let (_, recovered) = check_sample($name);
                if $name == "sample_with_a_bad_chunk_magic" {
                    assert!(recovered > 0, "expected resynchronised records");
                } else {
                    assert_eq!(recovered, 0, "{}", $name);
                }
            )*
        }

        #[test]
        fn every_sample_has_a_golden_test() {
            let mut covered = vec![$($name.to_string()),*];
            covered.sort();
            assert_eq!(covered, common::sample_names());
        }
    };
}

golden! {
    golden_security => "security",
    golden_system => "system",
    golden_sysmon => "sysmon",
    golden_new_user_security => "new-user-security",
    golden_application_no_crc32 => "Application_no_crc32",
    golden_bad_chunk_magic => "sample_with_a_bad_chunk_magic",
    golden_security_short_selected => "Security_short_selected",
    golden_msexchange_wec => "MSExchange_Management_wec",
    golden_hello_for_business => "HelloForBusiness-Operational",
}
