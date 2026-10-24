//! BinXML token-stream parser.
//!
//! The parser is iterative: open elements live on an explicit stack, so element
//! nesting never recurses on the Rust stack. Recursion only happens for
//! *fragments* (template definitions and embedded BinXML values), and that is
//! bounded by [`Limits::max_fragment_depth`].
//!
//! Every position is a chunk-relative offset because names and template
//! definitions are referenced by their offset inside the 64 KiB chunk. A name
//! or definition whose offset equals the current read position is stored
//! inline and must be skipped after decoding.

use super::template::{TemplateDef, TemplateValue, instantiate};
use super::token;
use crate::bytes::{Cursor, u16_at};
use crate::error::{EvtxError, Result};
use crate::model::{Attribute, Element, Node, Substitution};
use crate::value::{Guid, Value, ty};
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::Arc;

/// Resource limits that keep hostile input from exhausting stack or memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum nesting of fragments (record → template → embedded BinXML ...).
    pub max_fragment_depth: usize,
    /// Maximum element nesting inside one fragment.
    pub max_element_depth: usize,
    /// Maximum nodes created while instantiating one template instance.
    pub max_nodes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_fragment_depth: 8,
            max_element_depth: 64,
            max_nodes: 100_000,
        }
    }
}

/// What kind of stream is being parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Template definition: substitutions allowed, template instances not,
    /// element starts carry a 2-byte dependency identifier.
    Template,
    /// Record body or embedded BinXML value.
    Record,
}

/// Per-chunk decoding state: the chunk bytes plus name and template caches.
///
/// One context is used by one thread for one chunk; caches are keyed by
/// chunk-relative offset, which is what BinXML references use.
pub struct ChunkContext<'a> {
    data: &'a [u8],
    limits: Limits,
    names: HashMap<usize, Arc<str>>,
    templates: HashMap<usize, std::result::Result<Rc<TemplateDef>, EvtxError>>,
}

/// Parser state for one fragment.
struct Frame {
    stack: Vec<Element>,
    roots: Vec<Node>,
    /// Inside a start tag (between OpenStartElement and Close*Element).
    in_start_tag: bool,
    /// Attribute currently collecting value nodes.
    attr: Option<Attribute>,
    /// Pending processing-instruction target awaiting its data token.
    pi_target: Option<Arc<str>>,
}

impl Frame {
    fn new() -> Self {
        Frame {
            stack: Vec::new(),
            roots: Vec::new(),
            in_start_tag: false,
            attr: None,
            pi_target: None,
        }
    }

    fn flush_attr(&mut self) {
        if let Some(attr) = self.attr.take()
            && let Some(top) = self.stack.last_mut()
        {
            top.attributes.push(attr);
        }
    }

    /// Adds content either to the attribute being built or to the open element.
    fn push_content(&mut self, node: Node, tok: u8, offset: usize) -> Result<()> {
        if self.in_start_tag {
            match self.attr.as_mut() {
                Some(attr) => attr.value.push(node),
                None => {
                    return Err(EvtxError::UnexpectedToken {
                        token: tok,
                        offset,
                        context: "content inside a start tag without an attribute",
                    });
                }
            }
            return Ok(());
        }
        self.attach(node);
        Ok(())
    }

    fn attach(&mut self, node: Node) {
        match self.stack.last_mut() {
            Some(top) => top.children.push(node),
            None => self.roots.push(node),
        }
    }

    fn close(&mut self, tok: u8, offset: usize) -> Result<()> {
        let el = self.stack.pop().ok_or(EvtxError::UnexpectedToken {
            token: tok,
            offset,
            context: "close without an open element",
        })?;
        self.in_start_tag = false;
        self.attach(Node::Element(el));
        Ok(())
    }
}

impl<'a> ChunkContext<'a> {
    /// Creates a context over the full chunk bytes.
    pub fn new(data: &'a [u8], limits: Limits) -> Self {
        ChunkContext {
            data,
            limits,
            names: HashMap::new(),
            templates: HashMap::new(),
        }
    }

    /// The chunk bytes.
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    /// Number of distinct template definitions parsed so far.
    pub fn templates_seen(&self) -> usize {
        self.templates.values().filter(|t| t.is_ok()).count()
    }

    /// Decodes the name structure at `offset`:
    /// `u32 next-in-bucket, u16 hash, u16 char count, UTF-16 chars, u16 NUL`.
    pub fn name_at(&mut self, offset: usize) -> Result<Arc<str>> {
        if let Some(name) = self.names.get(&offset) {
            return Ok(name.clone());
        }
        let mut c = Cursor::new(self.data, offset, self.data.len());
        if offset >= self.data.len() {
            return Err(EvtxError::invalid("name offset", offset, "outside chunk"));
        }
        c.skip(6)?;
        let count = usize::from(c.u16()?);
        let name: Arc<str> = c.utf16(count)?.into();
        self.names.insert(offset, name.clone());
        Ok(name)
    }

    /// Reads a name reference at the cursor, skipping the name if it is inline.
    fn read_name(&mut self, cur: &mut Cursor<'a>) -> Result<Arc<str>> {
        let offset = cur.u32()? as usize;
        let name = self.name_at(offset)?;
        if offset == cur.pos() {
            let count = usize::from(u16_at(self.data, offset + 6)?);
            cur.skip(8 + count * 2 + 2)?;
        }
        Ok(name)
    }

    /// Parses (or fetches from cache) the template definition at `offset`.
    pub fn template_at(&mut self, offset: usize, depth: usize) -> Result<Rc<TemplateDef>> {
        if let Some(cached) = self.templates.get(&offset) {
            return cached.clone();
        }
        let parsed = self.parse_template(offset, depth);
        self.templates.insert(offset, parsed.clone());
        parsed
    }

    fn parse_template(&mut self, offset: usize, depth: usize) -> Result<Rc<TemplateDef>> {
        if offset < crate::chunk::CHUNK_HEADER_SIZE || offset >= self.data.len() {
            return Err(EvtxError::invalid(
                "template definition offset",
                offset,
                "outside the chunk's record area",
            ));
        }
        let mut c = Cursor::new(self.data, offset, self.data.len());
        c.skip(4)?; // offset of next definition in the same hash bucket
        let mut guid = [0u8; 16];
        guid.copy_from_slice(c.take(16)?);
        let data_size = c.u32()? as usize;
        let start = c.pos();
        if data_size > c.remaining() {
            return Err(EvtxError::Truncated {
                offset: start,
                need: data_size,
                available: c.remaining(),
            });
        }
        let mut body = Cursor::new(self.data, start, start + data_size);
        let nodes = self.parse_fragment(&mut body, Mode::Template, depth + 1)?;
        let root = nodes
            .into_iter()
            .find_map(|n| match n {
                Node::Element(e) => Some(e),
                _ => None,
            })
            .ok_or_else(|| EvtxError::invalid("template definition", offset, "no root element"))?;
        Ok(Rc::new(TemplateDef::new(
            offset,
            Guid(guid),
            data_size,
            root,
        )))
    }

    /// Parses a record's BinXML body `data[start..end]` into its root element.
    pub fn parse_record(&mut self, start: usize, end: usize) -> Result<Element> {
        let mut cur = Cursor::new(self.data, start, end);
        let nodes = self.parse_fragment(&mut cur, Mode::Record, 0)?;
        nodes
            .into_iter()
            .find_map(|n| match n {
                Node::Element(e) => Some(e),
                _ => None,
            })
            .ok_or_else(|| EvtxError::invalid("record body", start, "no root element"))
    }

    /// Parses tokens until EOF (or the end of the window) and returns top-level nodes.
    fn parse_fragment(
        &mut self,
        cur: &mut Cursor<'a>,
        mode: Mode,
        depth: usize,
    ) -> Result<Vec<Node>> {
        if depth > self.limits.max_fragment_depth {
            return Err(EvtxError::DepthLimit {
                limit: self.limits.max_fragment_depth,
                offset: cur.pos(),
            });
        }
        let mut f = Frame::new();
        while let Some(tok) = cur.peek_u8() {
            let offset = cur.pos();
            cur.skip(1)?;
            // Only element starts, values, attributes, CDATA and references take the flag.
            let base = match tok {
                0x41 | 0x45..=0x49 => tok & !token::MORE_FLAG,
                _ => tok,
            };
            match base {
                token::EOF => break,
                token::OPEN_START_ELEMENT => {
                    if f.in_start_tag {
                        return Err(EvtxError::UnexpectedToken {
                            token: tok,
                            offset,
                            context: "element start inside another start tag",
                        });
                    }
                    if f.stack.len() >= self.limits.max_element_depth {
                        return Err(EvtxError::DepthLimit {
                            limit: self.limits.max_element_depth,
                            offset,
                        });
                    }
                    if mode == Mode::Template {
                        cur.skip(2)?; // dependency identifier
                    }
                    cur.skip(4)?; // element data size
                    let name = self.read_name(cur)?;
                    if tok & token::MORE_FLAG != 0 {
                        cur.skip(4)?; // attribute list size
                    }
                    f.stack.push(Element::new(name));
                    f.in_start_tag = true;
                }
                token::CLOSE_START_ELEMENT => {
                    if !f.in_start_tag {
                        return Err(EvtxError::UnexpectedToken {
                            token: tok,
                            offset,
                            context: "close-start without a start tag",
                        });
                    }
                    f.flush_attr();
                    f.in_start_tag = false;
                }
                token::CLOSE_EMPTY_ELEMENT => {
                    if !f.in_start_tag {
                        return Err(EvtxError::UnexpectedToken {
                            token: tok,
                            offset,
                            context: "close-empty without a start tag",
                        });
                    }
                    f.flush_attr();
                    f.close(tok, offset)?;
                }
                token::CLOSE_ELEMENT => {
                    if f.in_start_tag {
                        return Err(EvtxError::UnexpectedToken {
                            token: tok,
                            offset,
                            context: "end element inside a start tag",
                        });
                    }
                    f.close(tok, offset)?;
                }
                token::VALUE => {
                    let value_type = cur.u8()?;
                    if value_type != ty::STRING {
                        return Err(EvtxError::UnsupportedValueType { value_type, offset });
                    }
                    let text = cur.len_prefixed_utf16()?;
                    f.push_content(Node::Value(Value::String(text)), tok, offset)?;
                }
                token::ATTRIBUTE => {
                    if !f.in_start_tag {
                        return Err(EvtxError::UnexpectedToken {
                            token: tok,
                            offset,
                            context: "attribute outside a start tag",
                        });
                    }
                    f.flush_attr();
                    let name = self.read_name(cur)?;
                    f.attr = Some(Attribute {
                        name,
                        value: Vec::new(),
                    });
                }
                token::CDATA_SECTION => {
                    let text = cur.len_prefixed_utf16()?;
                    f.push_content(Node::CData(text), tok, offset)?;
                }
                token::CHAR_REF => {
                    let ch = cur.u16()?;
                    f.push_content(Node::CharRef(ch), tok, offset)?;
                }
                token::ENTITY_REF => {
                    let name = self.read_name(cur)?;
                    f.push_content(Node::EntityRef(name), tok, offset)?;
                }
                token::PI_TARGET => {
                    let name = self.read_name(cur)?;
                    f.pi_target = Some(name);
                }
                token::PI_DATA => {
                    let data = cur.len_prefixed_utf16()?;
                    let target = f.pi_target.take().ok_or(EvtxError::UnexpectedToken {
                        token: tok,
                        offset,
                        context: "PI data without a PI target",
                    })?;
                    f.push_content(Node::ProcessingInstruction { target, data }, tok, offset)?;
                }
                token::TEMPLATE_INSTANCE => {
                    if mode == Mode::Template {
                        return Err(EvtxError::UnexpectedToken {
                            token: tok,
                            offset,
                            context: "template instance inside a template definition",
                        });
                    }
                    for el in self.parse_template_instance(cur, depth)? {
                        f.push_content(Node::Element(el), tok, offset)?;
                    }
                }
                token::NORMAL_SUBSTITUTION | token::OPTIONAL_SUBSTITUTION => {
                    if mode == Mode::Record {
                        return Err(EvtxError::UnexpectedToken {
                            token: tok,
                            offset,
                            context: "substitution outside a template definition",
                        });
                    }
                    let index = cur.u16()?;
                    let value_type = cur.u8()?;
                    let node = Node::Substitution(Substitution {
                        index,
                        value_type,
                        optional: base == token::OPTIONAL_SUBSTITUTION,
                    });
                    f.push_content(node, tok, offset)?;
                }
                token::FRAGMENT_HEADER => cur.skip(3)?, // major, minor, flags
                _ => return Err(EvtxError::UnknownToken { token: tok, offset }),
            }
        }
        if !f.stack.is_empty() {
            return Err(EvtxError::invalid(
                "BinXML fragment",
                cur.pos(),
                format!("{} element(s) left open", f.stack.len()),
            ));
        }
        Ok(f.roots)
    }

    /// Parses a template instance (after its 0x0C token) and instantiates it.
    fn parse_template_instance(
        &mut self,
        cur: &mut Cursor<'a>,
        depth: usize,
    ) -> Result<Vec<Element>> {
        cur.skip(1)?; // unknown, usually 1
        let _template_id = cur.u32()?;
        let def_offset = cur.u32()? as usize;
        if def_offset == cur.pos() {
            // Definition stored inline: parse it now, then step over it.
            self.template_at(def_offset, depth)?;
            cur.skip(20)?; // next offset + GUID
            let size = cur.u32()? as usize;
            cur.skip(size)?;
        }
        let template = self.template_at(def_offset, depth)?;

        let count = cur.u32()? as usize;
        if count.saturating_mul(4) > cur.remaining() {
            return Err(EvtxError::Truncated {
                offset: cur.pos(),
                need: count.saturating_mul(4),
                available: cur.remaining(),
            });
        }
        let mut descriptors = Vec::with_capacity(count);
        for _ in 0..count {
            let size = usize::from(cur.u16()?);
            let value_type = cur.u8()?;
            cur.skip(1)?; // padding
            descriptors.push((size, value_type));
        }
        let mut values = Vec::with_capacity(count);
        for (size, value_type) in descriptors {
            let offset = cur.pos();
            let bytes = cur.take(size)?;
            let value = if value_type == ty::BIN_XML {
                if size == 0 {
                    TemplateValue::Value(Value::Null)
                } else {
                    let mut sub = Cursor::new(self.data, offset, offset + size);
                    TemplateValue::Xml(self.parse_fragment(&mut sub, Mode::Record, depth + 1)?)
                }
            } else {
                TemplateValue::Value(Value::decode(value_type, bytes, offset)?)
            };
            values.push(value);
        }
        instantiate(&template, &mut values, self.limits.max_nodes)
    }
}
