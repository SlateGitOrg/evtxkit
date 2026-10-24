//! Node budgets (threat-model items T4 and T11) against real samples and
//! hand-built hostile files. The `#[ignore]`d tests are measurement tools used
//! by `scripts/hostile-rss.sh` and the README, not assertions.
#![allow(clippy::unwrap_used)]

mod common;

use common::builder::file;
use common::hostile::*;
use evtxkit::binxml::Limits;
use evtxkit::chunk::Chunk;
use evtxkit::{ChunkSlot, EvtxError, EvtxFile};

fn hits_budget(chunk: &Chunk<'_>, limits: Limits) -> bool {
    chunk
        .records_with(limits)
        .any(|r| matches!(r, Err(e) if matches!(e.error, EvtxError::ExpansionLimit { .. })))
}

fn sample_chunks(name: &str, mut f: impl FnMut(&Chunk<'_>)) {
    let file = EvtxFile::open(common::sample(&format!("{name}.evtx"))).unwrap();
    for i in 0..file.slot_count() {
        if let ChunkSlot::Chunk(c) = file.chunk(i) {
            f(&c);
        }
    }
}

/// Every sample decodes with budgets 100x (record) and 20x (chunk) smaller
/// than the defaults, so the defaults leave wide headroom for genuine logs.
#[test]
fn samples_fit_far_smaller_budgets() {
    let small = Limits {
        max_nodes: 1_000,
        max_chunk_nodes: 50_000,
        ..Limits::default()
    };
    for name in common::sample_names() {
        sample_chunks(&name, |c| assert!(!hits_budget(c, small), "{name}"));
    }
}

/// Smallest budget for which `fits` holds (binary search; `fits` is monotone).
fn smallest(fits: impl Fn(usize) -> bool) -> usize {
    let (mut lo, mut hi) = (0, 10_000_000);
    while lo < hi {
        let mid = (lo + hi) / 2;
        if fits(mid) { hi = mid } else { lo = mid + 1 }
    }
    lo
}

/// Prints the budget each sample actually needs, per record and per chunk.
/// `cargo test --release --test budget sample_budget_needs -- --ignored --nocapture`
#[test]
#[ignore]
fn sample_budget_needs() {
    let (mut all_rec, mut all_chunk) = (0, 0);
    for name in common::sample_names() {
        let (mut rec, mut chunk) = (0, 0);
        sample_chunks(&name, |c| {
            let unlimited = Limits {
                max_nodes: usize::MAX,
                max_chunk_nodes: usize::MAX,
                ..Limits::default()
            };
            rec = rec.max(smallest(|n| {
                !hits_budget(
                    c,
                    Limits {
                        max_nodes: n,
                        ..unlimited
                    },
                )
            }));
            chunk = chunk.max(smallest(|n| {
                !hits_budget(
                    c,
                    Limits {
                        max_chunk_nodes: n,
                        ..unlimited
                    },
                )
            }));
        });
        println!("{name}: per record {rec}, per chunk {chunk}");
        all_rec = all_rec.max(rec);
        all_chunk = all_chunk.max(chunk);
    }
    println!("all samples: per record {all_rec}, per chunk {all_chunk}");
}

/// Writes the hostile files measured by `scripts/hostile-rss.sh` into
/// `$EVTXKIT_HOSTILE_DIR`.
#[test]
#[ignore]
fn write_hostile_files() {
    let dir = std::env::var("EVTXKIT_HOSTILE_DIR").unwrap();
    let write = |name: &str, chunks: Vec<Vec<u8>>| {
        std::fs::write(format!("{dir}/{name}.evtx"), file(&chunks)).unwrap();
    };
    for n in [10, 100, 500] {
        write(&format!("A-array-{n}"), vec![array_clone_bomb(n)]);
    }
    for n in [5, 20, 400] {
        write(&format!("B-instances-{n}"), vec![multi_instance_bomb(n)]);
    }
    for n in [5, 20, 300] {
        write(&format!("C-records-{n}"), vec![many_records_bomb(n)]);
    }
    for n in [1_000, 25_000] {
        write(&format!("D-string-{n}"), vec![string_clone_bomb(16_000, n)]);
    }
    for copies in [64, 1024] {
        let chunks = (0..copies).map(|_| many_records_bomb(300)).collect();
        write(&format!("C-records-300-x{copies}"), chunks);
    }
}
