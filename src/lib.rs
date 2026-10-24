//! # evtxkit
//!
//! A from-scratch parser for the Windows XML Event Log (EVTX) format.
//!
//! * [`file`] — file header and chunk slots
//! * [`chunk`] — chunk header, CRC32 verification, record iteration
//! * [`record`] — record framing
//! * [`binxml`] — BinXML token stream, templates and substitutions
//! * [`value`] / [`model`] — typed values and the element tree
//! * [`render`] — JSONL and XML output
//! * [`pipeline`] — chunk-parallel, order-preserving processing
//! * [`fields`] / [`mapping`] / [`filter`] — flat field view, Sigma-style
//!   field mapping and field filter expressions
//! * [`stats`] — aggregate statistics
//!
//! ```no_run
//! use evtxkit::{EvtxFile, render};
//!
//! let file = EvtxFile::open("Security.evtx")?;
//! for record in file.records() {
//!     match record {
//!         Ok(r) => println!("{}", render::json::record_line(&r)),
//!         Err(e) => eprintln!("skipped: {e}"),
//!     }
//! }
//! # Ok::<(), evtxkit::EvtxError>(())
//! ```

pub mod binxml;
pub mod bytes;
pub mod chunk;
pub mod crc32;
pub mod error;
pub mod file;
pub mod model;
pub mod record;
pub mod time;
pub mod value;

pub use chunk::{Chunk, ChunkSlot, CrcStatus};
pub use error::{EvtxError, Result};
pub use file::EvtxFile;
pub use model::{Element, Node};
pub use record::{Record, RecordError};
pub use value::Value;
