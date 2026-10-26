//! Hand-built chunks that try to turn a few kilobytes into gigabytes of
//! decoded tree (threat-model item T4). Each returns one finished chunk.
//! Every shape fits easily in one 64 KiB chunk.

use super::builder::{ChunkBuilder, Val, v_str, v_u8_array};

/// `<E>%0<F>%1 x50</F></E>`, `%0` = UInt8 array of `items`, `%1` = a BinXML
/// value of 1,000 empty elements. Every array copy is charged its full deep
/// size (~50,000 units), not just its 3 direct nodes.
pub fn array_clone_bomb(items: usize) -> Vec<u8> {
    let mut b = ChunkBuilder::new();
    b.record(1, |b| {
        b.fragment_header();
        b.template_with_values_then_nested(
            |b| {
                b.open("E", false).close_start().sub(0, 0x84, false);
                b.open("F", false).close_start();
                for _ in 0..50 {
                    b.sub(1, 0x21, false);
                }
                b.end();
                b.end();
            },
            &[v_u8_array(items)],
            |b| {
                for _ in 0..1000 {
                    b.open("G", false).close_empty();
                }
            },
        );
        b.eof();
    });
    b.finish()
}

/// `<R><E>%0<F/> x1000</E></R>`: each instance with a 90-item array creates
/// ~90,000 nodes (just under one 100,000-node allowance), and the record keeps
/// all of them because the repeated `E` sits below the root.
fn wide_def(b: &mut ChunkBuilder) {
    b.open("R", false).close_start();
    b.open("E", false).close_start().sub(0, 0x84, false);
    for _ in 0..1000 {
        b.open("F", false).close_empty();
    }
    b.end();
    b.end();
}

/// One record holding `instances` template instances of [`wide_def`].
/// All instances share one per-record node budget.
pub fn multi_instance_bomb(instances: usize) -> Vec<u8> {
    let mut b = ChunkBuilder::new();
    b.record(1, |b| {
        b.fragment_header();
        let def = b.template_inline(wide_def, &[v_u8_array(90)]);
        for _ in 1..instances {
            b.template_ref(def, &[v_u8_array(90)]);
        }
        b.eof();
    });
    b.finish()
}

/// `records` small records, each one instance of [`wide_def`]. Every record
/// stays under the per-record budget; only a per-chunk budget stops this.
pub fn many_records_bomb(records: usize) -> Vec<u8> {
    let mut b = ChunkBuilder::new();
    let mut def = 0;
    b.record(1, |b| {
        b.fragment_header();
        def = b.template_inline(wide_def, &[v_u8_array(90)]);
        b.eof();
    });
    for id in 2..=records as u64 {
        b.record(id, |b| {
            b.fragment_header();
            b.template_ref(def, &[v_u8_array(90)]);
            b.eof();
        });
    }
    b.finish()
}

/// `<E>%0%1</E>`, `%0` = a string of `chars` UTF-16 units, `%1` = UInt8 array
/// of `items`. Each array copy clones the long string: few nodes, many bytes.
pub fn string_clone_bomb(chars: usize, items: usize) -> Vec<u8> {
    let long = "A".repeat(chars);
    let values: [Val; 2] = [v_str(&long), v_u8_array(items)];
    let mut b = ChunkBuilder::new();
    b.record(1, |b| {
        b.fragment_header();
        b.template_inline(
            |b| {
                b.open("E", false)
                    .close_start()
                    .sub(0, 0x01, false)
                    .sub(1, 0x84, false)
                    .end();
            },
            &values,
        );
        b.eof();
    });
    b.finish()
}
