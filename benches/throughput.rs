//! Throughput benchmark: chunk-parallel decoding with 1..N worker threads.
//!
//! Input: every decodable chunk of the committed samples, stitched `--copies`
//! times into one in-memory EVTX file (see `evtxkit::synth`). Two workloads:
//!
//! * `parse` — decode every record into its element tree;
//! * `dump`  — decode and render JSON Lines (what `evtxkit dump` does), with
//!   output bytes counted but discarded.
//!
//! Each configuration runs `--runs` times; the median wall time is reported.
//! Run with `cargo bench --bench throughput -- [--copies N] [--runs R] [--threads 1,2,4,8]`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use evtxkit::binxml::Limits;
use evtxkit::pipeline::{self, CrcPolicy, PipelineConfig};
use evtxkit::{EvtxFile, render, synth};
use std::path::PathBuf;
use std::time::Instant;

struct Opts {
    copies: usize,
    runs: usize,
    threads: Vec<usize>,
}

fn parse_opts() -> Opts {
    let mut o = Opts {
        copies: 16,
        runs: 5,
        threads: vec![1, 2, 4, 8],
    };
    let args: Vec<String> = std::env::args().collect();
    let mut i = 1;
    while i < args.len() {
        let next = args.get(i + 1).cloned().unwrap_or_default();
        match args[i].as_str() {
            "--copies" => o.copies = next.parse().expect("--copies N"),
            "--runs" => o.runs = next.parse().expect("--runs N"),
            "--threads" => {
                o.threads = next
                    .split(',')
                    .map(|t| t.trim().parse().expect("--threads 1,2,4"))
                    .collect()
            }
            _ => {
                i += 1;
                continue;
            }
        }
        i += 2;
    }
    o
}

/// Runs one workload and returns (records, output bytes).
fn workload(file: &EvtxFile, threads: usize, render_json: bool) -> (u64, u64) {
    let mut records = 0u64;
    let mut bytes = 0u64;
    pipeline::run(
        file,
        PipelineConfig::new(threads),
        |slot| {
            let batch = pipeline::decode_slot(slot, CrcPolicy::Report, Limits::default());
            let mut n = 0u64;
            let mut out = String::new();
            for r in batch.records.iter().flatten() {
                n += 1;
                if render_json {
                    render::json::write_record(&mut out, r);
                    out.push('\n');
                }
            }
            (n, out.len() as u64)
        },
        |(n, b): (u64, u64)| -> Result<(), ()> {
            records += n;
            bytes += b;
            Ok(())
        },
    )
    .expect("sink never fails");
    (records, bytes)
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(f64::total_cmp);
    v[v.len() / 2]
}

fn main() {
    let o = parse_opts();
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "evtx"))
        .collect();
    paths.sort();
    let sources: Vec<EvtxFile> = paths.iter().map(|p| EvtxFile::open(p).unwrap()).collect();
    let refs: Vec<&EvtxFile> = sources.iter().collect();
    let file = EvtxFile::from_bytes(synth::stitch(&refs, o.copies)).unwrap();
    let mib = file.bytes().len() as f64 / (1024.0 * 1024.0);
    let cores = std::thread::available_parallelism().map_or(1, usize::from);
    println!(
        "input: {} chunks, {mib:.1} MiB ({} copies of {} sample chunks); {cores} logical cores; median of {} runs",
        file.slot_count(),
        o.copies,
        file.slot_count() / o.copies.max(1),
        o.runs
    );
    println!();
    println!("| workload | threads | median s | MiB/s | records/s | speedup |");
    println!("|----------|--------:|---------:|------:|----------:|--------:|");
    for (name, json) in [("parse", false), ("dump", true)] {
        let mut base = None;
        for &t in &o.threads {
            workload(&file, t, json); // warm-up
            let mut times = Vec::with_capacity(o.runs);
            let mut recs = 0;
            for _ in 0..o.runs {
                let start = Instant::now();
                let (r, _) = workload(&file, t, json);
                times.push(start.elapsed().as_secs_f64());
                recs = r;
            }
            let secs = median(times);
            let b = *base.get_or_insert(secs);
            println!(
                "| {name} | {t} | {secs:.3} | {:.1} | {:.0} | {:.2}x |",
                mib / secs,
                recs as f64 / secs,
                b / secs
            );
        }
    }
}
