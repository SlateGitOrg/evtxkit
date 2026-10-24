//! The chunk-parallel pipeline must produce exactly the sequential output.
#![allow(clippy::unwrap_used)]

mod common;

use evtxkit::binxml::Limits;
use evtxkit::pipeline::{self, CrcPolicy, PipelineConfig};
use evtxkit::{EvtxFile, render, synth};

fn stitched(copies: usize) -> EvtxFile {
    let names = [
        "security.evtx",
        "system.evtx",
        "sample_with_a_bad_chunk_magic.evtx",
    ];
    let files: Vec<EvtxFile> = names
        .iter()
        .map(|n| EvtxFile::open(common::sample(n)).unwrap())
        .collect();
    let refs: Vec<&EvtxFile> = files.iter().collect();
    EvtxFile::from_bytes(synth::stitch(&refs, copies)).unwrap()
}

fn sequential_lines(f: &EvtxFile) -> Vec<String> {
    f.records()
        .map(|r| match r {
            Ok(r) => render::json::record_line(&r),
            Err(e) => render::json::error_line(&e),
        })
        .collect()
}

fn parallel_lines(f: &EvtxFile, cfg: PipelineConfig) -> Vec<String> {
    let mut out = Vec::new();
    pipeline::run(
        f,
        cfg,
        |slot| {
            pipeline::decode_slot(slot, CrcPolicy::Report, Limits::default())
                .records
                .iter()
                .map(|r| match r {
                    Ok(r) => render::json::record_line(r),
                    Err(e) => render::json::error_line(e),
                })
                .collect::<Vec<_>>()
        },
        |lines| -> Result<(), ()> {
            out.extend(lines);
            Ok(())
        },
    )
    .unwrap();
    out
}

#[test]
fn parallel_output_equals_sequential_for_any_thread_count_and_window() {
    let f = stitched(2);
    assert_eq!(f.slot_count(), 90);
    let want = sequential_lines(&f);
    assert_eq!(
        want.iter().filter(|l| !l.starts_with("{\"error\"")).count(),
        2 * (2261 + 1881 + 301)
    );
    for (threads, window) in [(1, 1), (2, 1), (3, 2), (8, 7), (16, 64)] {
        let got = parallel_lines(&f, PipelineConfig { threads, window });
        assert_eq!(got, want, "threads={threads} window={window}");
    }
}

#[test]
fn sink_errors_stop_the_workers() {
    let f = stitched(3);
    for threads in [1, 4] {
        let mut seen = 0;
        let res = pipeline::run(
            &f,
            PipelineConfig { threads, window: 2 },
            |slot| slot.index(),
            |i| {
                assert_eq!(i, seen, "results arrive in order");
                seen += 1;
                if i == 5 { Err("stop") } else { Ok(()) }
            },
        );
        assert_eq!(res, Err("stop"));
        assert_eq!(seen, 6);
    }
}

#[test]
fn empty_and_default_configs() {
    let empty = EvtxFile::from_bytes(synth::file_header(0, 1)).unwrap();
    let mut calls = 0;
    pipeline::run(
        &empty,
        PipelineConfig::default(),
        |_| (),
        |()| -> Result<(), ()> {
            calls += 1;
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(calls, 0);
    let cfg = PipelineConfig::new(0);
    assert_eq!((cfg.threads, cfg.window), (1, 4));
}
