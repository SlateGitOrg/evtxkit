//! BinXML features and failure modes exercised with hand-built chunks.
#![allow(clippy::unwrap_used)]

mod common;

use common::builder::*;
use evtxkit::binxml::Limits;
use evtxkit::pipeline::{CrcPolicy, decode_slot};
use evtxkit::{ChunkSlot, CrcStatus, EvtxError, EvtxFile, Record, RecordError, render};

fn records(chunk: Vec<u8>) -> Vec<Result<Record, RecordError>> {
    let f = EvtxFile::from_bytes(file(&[chunk])).unwrap();
    f.records().collect()
}

fn one(chunk: Vec<u8>) -> Record {
    let mut r = records(chunk);
    assert_eq!(r.len(), 1, "{r:?}");
    r.remove(0).unwrap()
}

fn one_err(chunk: Vec<u8>) -> EvtxError {
    let mut r = records(chunk);
    assert_eq!(r.len(), 1, "{r:?}");
    r.remove(0).unwrap_err().error
}

#[test]
fn template_instance_with_reuse() {
    let mut b = ChunkBuilder::new();
    let mut def = 0;
    b.record(10, |b| {
        b.fragment_header();
        def = b.template_inline(simple_event_def, &[v_u32(4624), v_str("alice")]);
        b.eof();
    });
    b.record(11, |b| {
        b.fragment_header();
        b.template_ref(def, &[v_u32(4625), v_str("bob")]);
        b.eof();
    });
    let recs: Vec<Record> = records(b.finish())
        .into_iter()
        .map(Result::unwrap)
        .collect();
    assert_eq!(recs.len(), 2);
    assert_eq!(recs[0].root.find("System/EventID").unwrap().text(), "4624");
    assert_eq!(recs[1].root.find("EventData/Data").unwrap().text(), "bob");
    assert_eq!(
        recs[1]
            .root
            .find("EventData/Data")
            .unwrap()
            .attr("Name")
            .unwrap(),
        "X"
    );
    assert!(recs.iter().all(|r| r.size_copy_valid && !r.recovered));
    let line = render::json::record_line(&recs[0]);
    let v: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(v["event"]["System"]["EventID"], 4624);
    assert_eq!(v["event"]["EventData"]["X"], "alice");
}

#[test]
fn arrays_expand_and_optional_empties_vanish() {
    let mut b = ChunkBuilder::new();
    b.record(1, |b| {
        b.fragment_header();
        b.template_inline(
            |b| {
                b.open("Event", false).close_start();
                b.open("Opt", true)
                    .attr("A")
                    .sub(0, 0x01, true)
                    .attr("B")
                    .text("b");
                b.close_empty();
                b.open("Data", false)
                    .close_start()
                    .sub(1, 0x81, false)
                    .end();
                b.open("Gone", false).close_start().sub(2, 0x01, true).end();
                b.end();
            },
            &[v_null(), v_str_array(&["x", "y", "z"]), v_str("")],
        );
        b.eof();
    });
    let r = one(b.finish());
    let opt = r.root.child("Opt").unwrap();
    assert_eq!(opt.attr("A"), None);
    assert_eq!(opt.attr("B").as_deref(), Some("b"));
    let data: Vec<String> = r
        .root
        .child_elements()
        .filter(|e| &*e.name == "Data")
        .map(|e| e.text())
        .collect();
    assert_eq!(data, ["x", "y", "z"]);
    assert!(r.root.child("Gone").unwrap().children.is_empty());
}

#[test]
fn direct_elements_with_cdata_refs_and_pi() {
    let mut b = ChunkBuilder::new();
    b.record(1, |b| {
        b.fragment_header();
        b.open("Event", true)
            .attr("k")
            .text("v")
            .char_ref(0x21)
            .close_start();
        b.open("T", false).close_start();
        b.text("a")
            .entity_ref("lt")
            .char_ref(0x42)
            .cdata("<c>")
            .pi("pi", "data");
        b.end();
        b.end();
        b.eof();
    });
    let r = one(b.finish());
    assert_eq!(r.root.attr("k").as_deref(), Some("v!"));
    assert_eq!(r.root.child("T").unwrap().text(), "a<B<c>");
    let xml = render::xml::record_document(&r);
    assert!(
        xml.contains("<T>a&lt;&#66;<![CDATA[<c>]]><?pi data?></T>"),
        "{xml}"
    );
}

#[test]
fn nested_binxml_values_are_spliced() {
    let mut b = ChunkBuilder::new();
    b.record(1, |b| {
        b.fragment_header();
        b.template_with_nested(
            |b| {
                b.open("Event", false).close_start();
                b.open("UserData", false)
                    .close_start()
                    .sub(0, 0x21, false)
                    .end();
                b.end();
            },
            |b| {
                b.open("LogFileCleared", false).close_start();
                b.open("SubjectUserName", false)
                    .close_start()
                    .text("admin")
                    .end();
                b.end();
            },
        );
        b.eof();
    });
    let r = one(b.finish());
    assert_eq!(
        r.root
            .find("UserData/LogFileCleared/SubjectUserName")
            .unwrap()
            .text(),
        "admin"
    );
    let f = evtxkit::fields::flatten(&r);
    assert_eq!(f.get("SubjectUserName"), Some("admin"));
}

#[test]
fn nested_template_instance_inside_binxml_value() {
    let mut b = ChunkBuilder::new();
    b.record(1, |b| {
        b.fragment_header();
        b.template_with_nested(
            |b| {
                b.open("Event", false)
                    .close_start()
                    .sub(0, 0x21, false)
                    .end();
            },
            |b| {
                b.template_inline(
                    |b| {
                        b.open("Inner", false)
                            .close_start()
                            .sub(0, 0x01, false)
                            .end();
                    },
                    &[v_str("deep")],
                );
            },
        );
        b.eof();
    });
    let r = one(b.finish());
    assert_eq!(r.root.find("Inner").unwrap().text(), "deep");
}

fn malformed(body: impl FnOnce(&mut ChunkBuilder)) -> EvtxError {
    let mut b = ChunkBuilder::new();
    b.record(1, |b| {
        b.fragment_header();
        body(b);
        b.eof();
    });
    one_err(b.finish())
}

#[test]
fn malformed_token_streams_are_errors_not_panics() {
    assert!(matches!(
        malformed(|b| {
            b.u8(0x7f);
        }),
        EvtxError::UnknownToken { token: 0x7f, .. }
    ));
    assert!(matches!(
        malformed(|b| {
            b.end();
        }),
        EvtxError::UnexpectedToken { .. }
    ));
    assert!(matches!(
        malformed(|b| {
            b.close_start();
        }),
        EvtxError::UnexpectedToken { .. }
    ));
    assert!(matches!(
        malformed(|b| {
            b.close_empty();
        }),
        EvtxError::UnexpectedToken { .. }
    ));
    assert!(matches!(
        malformed(|b| {
            b.attr("x");
        }),
        EvtxError::UnexpectedToken { .. }
    ));
    assert!(matches!(
        malformed(|b| {
            b.open("A", false).sub(0, 1, false);
        }),
        EvtxError::UnexpectedToken { .. }
    ));
    assert!(matches!(
        malformed(|b| {
            b.open("A", true).text("orphan");
        }),
        EvtxError::UnexpectedToken { .. }
    ));
    assert!(matches!(
        malformed(|b| {
            b.open("A", false).open("B", false);
        }),
        EvtxError::UnexpectedToken { .. }
    ));
    assert!(matches!(
        malformed(|b| {
            b.open("A", false).close_start().close_start();
        }),
        EvtxError::UnexpectedToken { .. }
    ));
    assert!(matches!(
        malformed(|b| {
            b.open("A", false).close_start().u8(0x0b).u16(0);
        }),
        EvtxError::UnexpectedToken { .. }
    ));
    assert!(matches!(
        malformed(|b| {
            b.open("A", false).close_start().u8(0x05).u8(0x08).u32(1);
        }),
        EvtxError::UnsupportedValueType { .. }
    ));
    assert!(matches!(
        malformed(|b| {
            b.open("A", false).close_start();
        }),
        EvtxError::Invalid {
            what: "BinXML fragment",
            ..
        }
    ));
    assert!(matches!(
        malformed(|b| {
            b.u8(0x01).u32(0).u32(0xfff0);
        }),
        EvtxError::Truncated { .. } | EvtxError::Invalid { .. }
    ));
    // Template instance pointing outside the record area.
    assert!(matches!(
        malformed(|b| {
            b.template_ref(16, &[]);
        }),
        EvtxError::Invalid { .. }
    ));
    // Template definition that itself contains a template instance.
    assert!(matches!(
        malformed(|b| {
            b.template_inline(
                |b| {
                    b.open("A", false).close_start().u8(0x0c);
                },
                &[],
            );
        }),
        EvtxError::UnexpectedToken { .. }
    ));
    // Template definition without a root element.
    assert!(matches!(
        malformed(|b| {
            b.template_inline(|_| {}, &[]);
        }),
        EvtxError::Invalid {
            what: "template definition",
            ..
        }
    ));
    // Substitution value whose size disagrees with its type.
    assert!(matches!(
        malformed(|b| {
            b.template_inline(simple_event_def, &[(0x08, vec![1, 2]), v_str("x")]);
        }),
        EvtxError::BadValueSize { .. }
    ));
    // A record whose body has no element at all.
    assert!(matches!(
        malformed(|_| {}),
        EvtxError::Invalid {
            what: "record body",
            ..
        }
    ));
    // Substitution count larger than the remaining bytes.
    assert!(matches!(
        malformed(|b| {
            let def = b.template_inline(simple_event_def, &[v_u32(1), v_str("a")]);
            b.u8(0x0c).u8(1).u32(0).u32(def).u32(0xffff_ffff);
        }),
        EvtxError::Truncated { .. }
    ));
}

#[test]
fn element_depth_is_limited() {
    let err = malformed(|b| {
        for _ in 0..100 {
            b.open("D", false).close_start();
        }
    });
    assert!(
        matches!(err, EvtxError::DepthLimit { limit: 64, .. }),
        "{err:?}"
    );
}

#[test]
fn fragment_depth_and_expansion_limits() {
    let mut b = ChunkBuilder::new();
    b.record(1, |b| {
        b.fragment_header();
        b.template_inline(
            |b| {
                b.open("E", false).close_start();
                for i in 0..4 {
                    b.sub(i, 0x81, false);
                }
                b.end();
            },
            &[
                v_str_array(&["a", "b", "c", "d"]),
                v_str_array(&["a", "b", "c", "d"]),
                v_str_array(&["a", "b", "c", "d"]),
                v_str_array(&["a", "b", "c", "d"]),
            ],
        );
        b.eof();
    });
    let data = file(&[b.finish()]);
    let f = EvtxFile::from_bytes(data).unwrap();
    let ChunkSlot::Chunk(chunk) = f.chunk(0) else {
        panic!("chunk")
    };
    let unlimited: Vec<_> = chunk.records().collect();
    assert!(unlimited[0].is_ok());
    let tight = Limits {
        max_nodes: 50,
        ..Limits::default()
    };
    let limited: Vec<_> = chunk.records_with(tight).collect();
    assert!(matches!(
        limited[0].as_ref().unwrap_err().error,
        EvtxError::ExpansionLimit { limit: 50 }
    ));
    let shallow = Limits {
        max_fragment_depth: 0,
        ..Limits::default()
    };
    let limited: Vec<_> = chunk.records_with(shallow).collect();
    assert!(matches!(
        limited[0].as_ref().unwrap_err().error,
        EvtxError::DepthLimit { limit: 0, .. }
    ));
}

#[test]
fn framing_errors_resynchronise() {
    let mut b = ChunkBuilder::new();
    b.record(1, |b| {
        b.fragment_header().open("A", false).close_empty().eof();
    });
    // 40 bytes of garbage between records.
    b.raw(&[0x55; 40]);
    b.record(2, |b| {
        b.fragment_header().open("B", false).close_empty().eof();
    });
    let out = records(b.finish());
    assert_eq!(out.len(), 3, "{out:?}");
    assert!(out[0].as_ref().is_ok_and(|r| !r.recovered));
    let err = out[1].as_ref().unwrap_err();
    assert!(matches!(
        err.error,
        EvtxError::BadSignature { what: "record", .. }
    ));
    assert_eq!(err.record_id, None);
    assert!(
        out[2]
            .as_ref()
            .is_ok_and(|r| r.recovered && r.record_id == 2)
    );
}

#[test]
fn crc_states_and_policies() {
    let build = |flags: u32| {
        let mut b = ChunkBuilder::new();
        b.flags = flags;
        b.record(1, |b| {
            b.fragment_header().open("A", false).close_empty().eof();
        });
        b.finish()
    };
    let good = build(0);
    let f = EvtxFile::from_bytes(file(std::slice::from_ref(&good))).unwrap();
    let ChunkSlot::Chunk(c) = f.chunk(0) else {
        panic!()
    };
    assert_eq!(
        (c.header_crc, c.records_crc),
        (CrcStatus::Valid, CrcStatus::Valid)
    );
    assert_eq!(c.template_offsets(), Vec::<usize>::new());
    assert!(c.common_string_offsets().is_empty());

    let mut tampered = good.clone();
    tampered[520] ^= 0xff; // record id byte, inside the CRC-covered record area
    tampered[60] ^= 0xff; // inside the CRC-covered header
    let f = EvtxFile::from_bytes(file(&[tampered])).unwrap();
    let ChunkSlot::Chunk(c) = f.chunk(0) else {
        panic!()
    };
    assert!(matches!(c.header_crc, CrcStatus::Mismatch { .. }));
    assert!(matches!(c.records_crc, CrcStatus::Mismatch { .. }));
    let report = decode_slot(f.chunk(0), CrcPolicy::Report, Limits::default());
    assert!(!report.info.skipped);
    let skip = decode_slot(f.chunk(0), CrcPolicy::Skip, Limits::default());
    assert!(skip.info.skipped);
    assert!(skip.records.iter().all(Result::is_err));

    let f = EvtxFile::from_bytes(file(&[build(0x4)])).unwrap();
    let ChunkSlot::Chunk(c) = f.chunk(0) else {
        panic!()
    };
    assert_eq!(c.records_crc, CrcStatus::Disabled);
    assert!(c.crc_ok());
}

#[test]
fn template_and_string_tables_are_walked() {
    let f = EvtxFile::open(common::sample("security.evtx")).unwrap();
    let ChunkSlot::Chunk(c) = f.chunk(0) else {
        panic!()
    };
    let templates = c.template_offsets();
    assert!(!templates.is_empty());
    // Every pointer-table entry must parse as a template that decoding also uses.
    let mut it = c.records();
    assert!(it.by_ref().all(|r| r.is_ok()));
    assert_eq!(it.templates_seen(), templates.len());
    assert!(!c.common_string_offsets().is_empty());
    // A self-referencing bucket chain terminates.
    let mut data = c.data().to_vec();
    let first = templates[0] as u32;
    data[first as usize..first as usize + 4].copy_from_slice(&first.to_le_bytes());
    let looped = evtxkit::chunk::Chunk::parse(0, 4096, &data);
    let ChunkSlot::Chunk(lc) = looped else {
        panic!()
    };
    assert!(lc.template_offsets().len() <= templates.len());
}
