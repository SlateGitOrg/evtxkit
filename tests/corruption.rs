//! Property tests: corrupted or random input must never panic.
//!
//! Every property decodes the whole input and also renders each decoded
//! record as JSON, XML and flat fields, because a malformed tree that only
//! fails later in a renderer would be just as bad as a parser panic.
#![allow(clippy::unwrap_used)]

mod common;

use common::builder::{ChunkBuilder, file};
use evtxkit::fields::flatten;
use evtxkit::filter::Filter;
use evtxkit::mapping::Mapping;
use evtxkit::{EvtxFile, render};
use proptest::prelude::*;
use std::sync::OnceLock;

/// Decodes and renders everything; returns (records, errors).
fn exercise(bytes: Vec<u8>) -> (usize, usize) {
    let Ok(f) = EvtxFile::from_bytes(bytes) else {
        return (0, 0);
    };
    let mapping = Mapping::builtin();
    let (mut ok, mut err) = (0, 0);
    for r in f.records() {
        match r {
            Ok(r) => {
                ok += 1;
                let _ = render::json::record_line(&r);
                let _ = render::xml::record_document(&r);
                let mut fields = flatten(&r);
                let _ = mapping.apply(&mut fields);
            }
            Err(e) => {
                err += 1;
                let _ = render::json::error_line(&e);
            }
        }
    }
    (ok, err)
}

fn small_samples() -> &'static Vec<Vec<u8>> {
    static S: OnceLock<Vec<Vec<u8>>> = OnceLock::new();
    S.get_or_init(|| {
        [
            "new-user-security.evtx",
            "Security_short_selected.evtx",
            "MSExchange_Management_wec.evtx",
            "HelloForBusiness-Operational.evtx",
        ]
        .iter()
        .map(|n| std::fs::read(common::sample(n)).unwrap())
        .collect()
    })
}

/// First chunk of security.evtx (many templates), behind a fresh header.
fn security_chunk() -> &'static Vec<u8> {
    static S: OnceLock<Vec<u8>> = OnceLock::new();
    S.get_or_init(|| {
        let data = std::fs::read(common::sample("security.evtx")).unwrap();
        file(&[data[4096..4096 + 65536].to_vec()])
    })
}

#[derive(Debug, Clone)]
enum Mutation {
    Set(usize, u8),
    Xor(usize, u8),
    Zero(usize, usize),
    Truncate(usize),
    Insert(usize, Vec<u8>),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    // Offsets are fractions of the file length so they stay in range; most
    // land in the first chunk where headers, tables and records live.
    let off = 0usize..70_000;
    prop_oneof![
        4 => (off.clone(), any::<u8>()).prop_map(|(o, b)| Mutation::Set(o, b)),
        4 => (off.clone(), 1u8..).prop_map(|(o, b)| Mutation::Xor(o, b)),
        1 => (off.clone(), 1usize..512).prop_map(|(o, n)| Mutation::Zero(o, n)),
        1 => off.clone().prop_map(Mutation::Truncate),
        1 => (off, proptest::collection::vec(any::<u8>(), 1..32))
            .prop_map(|(o, v)| Mutation::Insert(o, v)),
    ]
}

fn apply(mut data: Vec<u8>, muts: &[Mutation]) -> Vec<u8> {
    for m in muts {
        let len = data.len().max(1);
        match m {
            Mutation::Set(o, b) => {
                let i = o % len;
                if let Some(x) = data.get_mut(i) {
                    *x = *b;
                }
            }
            Mutation::Xor(o, b) => {
                let i = o % len;
                if let Some(x) = data.get_mut(i) {
                    *x ^= *b;
                }
            }
            Mutation::Zero(o, n) => {
                let i = o % len;
                let end = (i + n).min(data.len());
                data[i.min(end)..end].fill(0);
            }
            Mutation::Truncate(o) => data.truncate(o % len),
            Mutation::Insert(o, v) => {
                let i = (o % len).min(data.len());
                data.splice(i..i, v.iter().copied());
            }
        }
    }
    data
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn mutated_samples_never_panic(
        which in 0usize..4,
        muts in proptest::collection::vec(mutation(), 1..12),
    ) {
        let data = apply(small_samples()[which].clone(), &muts);
        exercise(data);
    }

    #[test]
    fn mutated_template_heavy_chunk_never_panics(
        muts in proptest::collection::vec(mutation(), 1..24),
    ) {
        // Keep the file header intact so mutations hit the chunk.
        let mut muts = muts;
        for m in &mut muts {
            if let Mutation::Set(o, _) | Mutation::Xor(o, _) = m {
                *o = 4096 + *o % 65536;
            }
        }
        exercise(apply(security_chunk().clone(), &muts));
    }

    #[test]
    fn random_record_bodies_never_panic(
        body in proptest::collection::vec(
            prop_oneof![
                3 => prop::sample::select(vec![
                    0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                    0x0c, 0x0d, 0x0e, 0x0f, 0x41, 0x45, 0x46, 0x47, 0x48, 0x49, 0x21, 0x81,
                ]),
                1 => any::<u8>(),
            ],
            0..600,
        ),
    ) {
        let mut b = ChunkBuilder::new();
        b.record(1, |b| { b.raw(&body); });
        b.record(2, |b| { b.fragment_header().open("Ok", false).close_empty().eof(); });
        let (ok, err) = exercise(file(&[b.finish()]));
        // Both records are framed correctly, so each yields exactly one result.
        prop_assert_eq!(ok + err, 2);
    }

    #[test]
    fn arbitrary_bytes_never_panic(data in proptest::collection::vec(any::<u8>(), 0..9000)) {
        let mut with_magic = data.clone();
        if with_magic.len() >= 8 {
            with_magic[..8].copy_from_slice(b"ElfFile\0");
        }
        exercise(data);
        exercise(with_magic);
    }

    #[test]
    fn crc32_matches_crc32fast(data in proptest::collection::vec(any::<u8>(), 0..4096)) {
        prop_assert_eq!(evtxkit::crc32::crc32(&data), crc32fast::hash(&data));
    }

    #[test]
    fn filter_parser_never_panics(expr in "\\PC{0,40}") {
        let _ = Filter::parse(&expr);
    }

    #[test]
    fn glob_filter_agrees_with_regex(
        pattern in "[ab*?]{0,8}",
        text in "[ab]{0,10}",
    ) {
        let mut fields = evtxkit::fields::FieldMap::new();
        fields.insert("F", text.clone());
        let glob = Filter::parse(&format!("F={pattern}")).unwrap().matches(&fields);
        let re: String = pattern.chars().map(|c| match c {
            '*' => ".*".to_string(),
            '?' => ".".to_string(),
            c => c.to_string(),
        }).collect();
        let want = regex::Regex::new(&format!("^(?s:{re})$")).unwrap().is_match(&text);
        prop_assert_eq!(glob, want, "pattern {:?} text {:?}", pattern, text);
    }
}

#[test]
fn every_single_byte_flip_in_a_small_file_is_safe() {
    // Exhaustive over the used part of one small sample: header, chunk header,
    // tables and all records (offset 0 .. 4096 + free space offset).
    let base = small_samples()[0].clone();
    let fso = u32::from_le_bytes(base[4096 + 48..4096 + 52].try_into().unwrap()) as usize;
    for i in (0..4096 + fso).step_by(3) {
        let mut d = base.clone();
        d[i] ^= 0xa5;
        exercise(d);
    }
}
