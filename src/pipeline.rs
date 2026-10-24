//! Chunk-parallel, order-preserving processing.
//!
//! EVTX chunks are self-contained (each has its own string and template
//! tables), so decoding parallelises at chunk granularity with no shared
//! state. [`run`] distributes chunk indexes to `threads` workers through an
//! atomic counter and hands results to a single sink **in file order**:
//!
//! ```text
//!   next: AtomicUsize ──► worker 0 ─┐
//!                     ──► worker 1 ─┼─ sync_channel(window) ─► reorder buffer ─► sink
//!                     ──► worker N ─┘        (index, T)          (BTreeMap)
//! ```
//!
//! Backpressure: a worker holding chunk `i` waits until `i < emitted + window`,
//! where `emitted` counts results already passed to the sink. At most
//! `window + threads` chunk results are therefore alive at once, so memory is
//! O(window) regardless of file size. The lowest outstanding index is always
//! allowed to proceed, so the scheme cannot deadlock. If the sink fails (for
//! example a closed stdout pipe) workers are told to stop.

use crate::binxml::Limits;
use crate::chunk::{ChunkSlot, CrcStatus};
use crate::error::EvtxError;
use crate::file::EvtxFile;
use crate::record::{Record, RecordError};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, mpsc};

/// Tuning for [`run`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PipelineConfig {
    /// Worker threads (1 = run on the calling thread).
    pub threads: usize,
    /// Maximum chunks decoded ahead of the sink.
    pub window: usize,
}

impl PipelineConfig {
    /// `threads` workers with a window of four chunks per worker.
    pub fn new(threads: usize) -> Self {
        let threads = threads.max(1);
        PipelineConfig {
            threads,
            window: threads * 4,
        }
    }
}

impl Default for PipelineConfig {
    fn default() -> Self {
        Self::new(std::thread::available_parallelism().map_or(1, usize::from))
    }
}

struct Gate {
    emitted: Mutex<usize>,
    cv: Condvar,
    abort: AtomicBool,
}

impl Gate {
    fn lock(&self) -> MutexGuard<'_, usize> {
        // A poisoned lock only means another thread panicked; the counter is still valid.
        self.emitted.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// Applies `map` to every chunk slot of `file` and feeds the results to `sink`
/// in slot order. Returns the sink's first error, after stopping the workers.
pub fn run<T, E, M, S>(file: &EvtxFile, cfg: PipelineConfig, map: M, mut sink: S) -> Result<(), E>
where
    T: Send,
    M: Fn(ChunkSlot<'_>) -> T + Sync,
    S: FnMut(T) -> Result<(), E>,
{
    let total = file.slot_count();
    let threads = cfg.threads.clamp(1, total.max(1));
    if threads == 1 {
        for i in 0..total {
            sink(map(file.chunk(i)))?;
        }
        return Ok(());
    }
    let window = cfg.window.max(1);
    let next = AtomicUsize::new(0);
    let gate = Gate {
        emitted: Mutex::new(0),
        cv: Condvar::new(),
        abort: AtomicBool::new(false),
    };
    let (tx, rx) = mpsc::sync_channel::<(usize, T)>(window);

    std::thread::scope(|scope| {
        for _ in 0..threads {
            let tx = tx.clone();
            let (next, gate, map) = (&next, &gate, &map);
            scope.spawn(move || {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= total {
                        break;
                    }
                    let mut emitted = gate.lock();
                    while i >= *emitted + window && !gate.abort.load(Ordering::Acquire) {
                        emitted = gate.cv.wait(emitted).unwrap_or_else(|e| e.into_inner());
                    }
                    drop(emitted);
                    if gate.abort.load(Ordering::Acquire) {
                        break;
                    }
                    if tx.send((i, map(file.chunk(i)))).is_err() {
                        break;
                    }
                }
            });
        }
        drop(tx);

        let gate = &gate;
        let result = (move || {
            let mut pending = BTreeMap::new();
            let mut next_emit = 0usize;
            for (i, out) in rx {
                pending.insert(i, out);
                while let Some(out) = pending.remove(&next_emit) {
                    sink(out)?;
                    next_emit += 1;
                    *gate.lock() = next_emit;
                    gate.cv.notify_all();
                }
            }
            Ok(())
        })();
        if result.is_err() {
            gate.abort.store(true, Ordering::Release);
            gate.cv.notify_all();
        }
        result
    })
}

/// What a chunk slot turned out to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotKind {
    /// A decodable chunk.
    Chunk,
    /// All-zero slot.
    Empty,
    /// Undecodable slot.
    Corrupt,
}

/// Whether chunks with CRC32 mismatches are decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CrcPolicy {
    /// Verify and report mismatches, but decode the chunk anyway (default;
    /// dirty logs routinely have stale record checksums).
    #[default]
    Report,
    /// Skip chunks whose header or record checksum does not verify.
    Skip,
}

/// Per-slot summary produced by [`decode_slot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotInfo {
    /// Slot index.
    pub index: usize,
    /// Classification.
    pub kind: SlotKind,
    /// Header checksum status (chunks only).
    pub header_crc: Option<CrcStatus>,
    /// Record-area checksum status (chunks only).
    pub records_crc: Option<CrcStatus>,
    /// First/last record id from the chunk header.
    pub record_id_range: Option<(u64, u64)>,
    /// Template definitions decoded in this chunk.
    pub templates: usize,
    /// True if the chunk was skipped by [`CrcPolicy::Skip`].
    pub skipped: bool,
}

/// All records of one slot plus its summary.
#[derive(Debug, Clone)]
pub struct SlotBatch {
    /// Summary.
    pub info: SlotInfo,
    /// Records and record-level errors in file order.
    pub records: Vec<Result<Record, RecordError>>,
}

/// Decodes every record of a slot according to `policy`.
pub fn decode_slot(slot: ChunkSlot<'_>, policy: CrcPolicy, limits: Limits) -> SlotBatch {
    match slot {
        ChunkSlot::Empty { index } => SlotBatch {
            info: SlotInfo {
                index,
                kind: SlotKind::Empty,
                header_crc: None,
                records_crc: None,
                record_id_range: None,
                templates: 0,
                skipped: false,
            },
            records: Vec::new(),
        },
        ChunkSlot::Corrupt { index, error } => SlotBatch {
            info: SlotInfo {
                index,
                kind: SlotKind::Corrupt,
                header_crc: None,
                records_crc: None,
                record_id_range: None,
                templates: 0,
                skipped: false,
            },
            records: vec![Err(RecordError {
                chunk_index: index,
                file_offset: crate::file::FILE_HEADER_SIZE + index * crate::chunk::CHUNK_SIZE,
                record_id: None,
                error,
            })],
        },
        ChunkSlot::Chunk(chunk) => {
            let mut info = SlotInfo {
                index: chunk.index,
                kind: SlotKind::Chunk,
                header_crc: Some(chunk.header_crc),
                records_crc: Some(chunk.records_crc),
                record_id_range: Some((chunk.header.first_record_id, chunk.header.last_record_id)),
                templates: 0,
                skipped: false,
            };
            if policy == CrcPolicy::Skip && !chunk.crc_ok() {
                info.skipped = true;
                let error =
                    EvtxError::invalid("chunk checksum", chunk.file_offset, "CRC32 mismatch");
                return SlotBatch {
                    info,
                    records: vec![Err(RecordError {
                        chunk_index: chunk.index,
                        file_offset: chunk.file_offset,
                        record_id: None,
                        error,
                    })],
                };
            }
            let mut iter = chunk.records_with(limits);
            let records: Vec<_> = iter.by_ref().collect();
            info.templates = iter.templates_seen();
            SlotBatch { info, records }
        }
    }
}
