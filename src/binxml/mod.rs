//! BinXML: Microsoft's binary XML encoding used inside EVTX records.
//!
//! A record body is a token stream. Most records consist of a single
//! *template instance*: a reference to a template definition (an XML skeleton
//! with numbered substitution placeholders, stored once per chunk) followed by
//! an array of typed values. [`parser`] turns token streams into
//! [`crate::model::Element`] trees and [`template`] instantiates definitions.
//! See `docs/FORMAT.md` for the byte-level layout.

pub mod parser;
pub mod template;

pub use parser::{ChunkContext, Limits};

/// BinXML token bytes. Tokens 0x01-0x09 may carry the 0x40 "more data" flag.
pub mod token {
    #![allow(missing_docs)]
    pub const EOF: u8 = 0x00;
    pub const OPEN_START_ELEMENT: u8 = 0x01;
    pub const CLOSE_START_ELEMENT: u8 = 0x02;
    pub const CLOSE_EMPTY_ELEMENT: u8 = 0x03;
    pub const CLOSE_ELEMENT: u8 = 0x04;
    pub const VALUE: u8 = 0x05;
    pub const ATTRIBUTE: u8 = 0x06;
    pub const CDATA_SECTION: u8 = 0x07;
    pub const CHAR_REF: u8 = 0x08;
    pub const ENTITY_REF: u8 = 0x09;
    pub const PI_TARGET: u8 = 0x0a;
    pub const PI_DATA: u8 = 0x0b;
    pub const TEMPLATE_INSTANCE: u8 = 0x0c;
    pub const NORMAL_SUBSTITUTION: u8 = 0x0d;
    pub const OPTIONAL_SUBSTITUTION: u8 = 0x0e;
    pub const FRAGMENT_HEADER: u8 = 0x0f;
    /// Flag bit: element has attributes / more attributes follow / etc.
    pub const MORE_FLAG: u8 = 0x40;
}
