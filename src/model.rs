//! The XML-like tree produced for every record.
//!
//! A record's BinXML expands into an [`Element`] tree. Values keep their
//! decoded type ([`Value`]) so renderers can emit native JSON numbers and the
//! field layer can compare numerically. Names are reference-counted because
//! the same element/attribute names repeat in every record of a chunk.

use crate::value::Value;
use std::sync::Arc;

/// A placeholder inside a template definition (MS-EVEN6 substitution tokens).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Substitution {
    /// Index into the template instance's value array.
    pub index: u16,
    /// Declared value type (informational; the instance's descriptor wins).
    pub value_type: u8,
    /// Optional substitutions are dropped when the value is empty.
    pub optional: bool,
}

/// Content of an element or attribute value.
#[derive(Debug, Clone, PartialEq)]
pub enum Node {
    /// A child element.
    Element(Element),
    /// A typed value (literal text is `Value::String`).
    Value(Value),
    /// A numeric character reference (`&#NNN;`).
    CharRef(u16),
    /// A named entity reference (`&name;`).
    EntityRef(Arc<str>),
    /// A CDATA section.
    CData(String),
    /// A processing instruction.
    ProcessingInstruction {
        /// PI target name.
        target: Arc<str>,
        /// PI data.
        data: String,
    },
    /// Unresolved substitution; only present in template definitions.
    Substitution(Substitution),
}

/// An attribute: a name plus a sequence of content nodes.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    /// Attribute name.
    pub name: Arc<str>,
    /// Value nodes, concatenated when rendered.
    pub value: Vec<Node>,
}

/// An element with attributes and children.
#[derive(Debug, Clone, PartialEq)]
pub struct Element {
    /// Element name.
    pub name: Arc<str>,
    /// Attributes in document order.
    pub attributes: Vec<Attribute>,
    /// Children in document order.
    pub children: Vec<Node>,
}

/// Resolves the five predefined XML entities; unknown names render as `&name;`.
pub fn entity_text(name: &str, out: &mut String) {
    match name {
        "amp" => out.push('&'),
        "lt" => out.push('<'),
        "gt" => out.push('>'),
        "quot" => out.push('"'),
        "apos" => out.push('\''),
        other => {
            out.push('&');
            out.push_str(other);
            out.push(';');
        }
    }
}

impl Node {
    /// Appends this node's text (elements contribute their full text content).
    pub fn write_text(&self, out: &mut String) {
        match self {
            Node::Element(e) => e.write_text_content(out),
            Node::Value(v) => v.write_text(out),
            Node::CharRef(c) => {
                out.push(char::from_u32(u32::from(*c)).unwrap_or(char::REPLACEMENT_CHARACTER));
            }
            Node::EntityRef(name) => entity_text(name, out),
            Node::CData(s) => out.push_str(s),
            Node::ProcessingInstruction { .. } | Node::Substitution(_) => {}
        }
    }

    /// True for nodes that render as character data.
    pub fn is_text(&self) -> bool {
        matches!(
            self,
            Node::Value(_) | Node::CharRef(_) | Node::EntityRef(_) | Node::CData(_)
        )
    }
}

impl Attribute {
    /// The attribute value as text.
    pub fn text(&self) -> String {
        let mut s = String::new();
        for n in &self.value {
            n.write_text(&mut s);
        }
        s
    }
}

impl Element {
    /// Creates an element with no attributes or children.
    pub fn new(name: impl Into<Arc<str>>) -> Self {
        Element {
            name: name.into(),
            attributes: Vec::new(),
            children: Vec::new(),
        }
    }

    /// Iterates over direct child elements.
    pub fn child_elements(&self) -> impl Iterator<Item = &Element> {
        self.children.iter().filter_map(|n| match n {
            Node::Element(e) => Some(e),
            _ => None,
        })
    }

    /// First direct child element called `name`.
    pub fn child(&self, name: &str) -> Option<&Element> {
        self.child_elements().find(|e| &*e.name == name)
    }

    /// Follows a `/`-separated path of child element names.
    pub fn find(&self, path: &str) -> Option<&Element> {
        path.split('/')
            .filter(|p| !p.is_empty())
            .try_fold(self, |el, part| el.child(part))
    }

    /// Value of attribute `name`, as text.
    pub fn attr(&self, name: &str) -> Option<String> {
        self.attributes
            .iter()
            .find(|a| &*a.name == name)
            .map(Attribute::text)
    }

    /// True if any direct child is an element.
    pub fn has_element_children(&self) -> bool {
        self.children.iter().any(|n| matches!(n, Node::Element(_)))
    }

    /// Concatenated character data of direct (non-element) children.
    pub fn text(&self) -> String {
        let mut s = String::new();
        for n in self.children.iter().filter(|n| n.is_text()) {
            n.write_text(&mut s);
        }
        s
    }

    /// The single typed value if the element's content is exactly one value.
    pub fn single_value(&self) -> Option<&Value> {
        match self.children.as_slice() {
            [Node::Value(v)] => Some(v),
            _ => None,
        }
    }

    fn write_text_content(&self, out: &mut String) {
        for n in &self.children {
            n.write_text(out);
        }
    }

    /// Total number of elements in this subtree (including `self`).
    pub fn element_count(&self) -> usize {
        1 + self
            .child_elements()
            .map(Element::element_count)
            .sum::<usize>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(s: &str) -> Node {
        Node::Value(Value::String(s.into()))
    }

    #[test]
    fn navigation_and_text() {
        let mut event = Element::new("Event");
        let mut system = Element::new("System");
        let mut id = Element::new("EventID");
        id.children.push(Node::Value(Value::UInt16(4624)));
        id.attributes.push(Attribute {
            name: "Qualifiers".into(),
            value: vec![text("0")],
        });
        system.children.push(Node::Element(id));
        event.children.push(Node::Element(system));
        let mut data = Element::new("Data");
        data.children.extend([
            text("a"),
            Node::EntityRef("amp".into()),
            Node::CharRef(0x42),
            Node::CData("c".into()),
            Node::EntityRef("nbsp".into()),
            Node::ProcessingInstruction {
                target: "t".into(),
                data: "d".into(),
            },
        ]);
        event.children.push(Node::Element(data));

        let id = event.find("System/EventID").unwrap();
        assert_eq!(id.text(), "4624");
        assert_eq!(id.single_value(), Some(&Value::UInt16(4624)));
        assert_eq!(id.attr("Qualifiers").as_deref(), Some("0"));
        assert_eq!(id.attr("Missing"), None);
        assert!(event.find("System/Nope").is_none());
        assert_eq!(event.child("Data").unwrap().text(), "a&BC&nbsp;");
        assert!(event.has_element_children());
        assert!(!id.has_element_children());
        assert_eq!(event.element_count(), 4);
        let mut all = String::new();
        Node::Element(event).write_text(&mut all);
        assert_eq!(all, "4624a&BC&nbsp;");
    }

    #[test]
    fn entities() {
        let mut s = String::new();
        for e in ["amp", "lt", "gt", "quot", "apos"] {
            entity_text(e, &mut s);
        }
        assert_eq!(s, "&<>\"'");
        let mut s = String::new();
        Node::CharRef(0xd800).write_text(&mut s);
        assert_eq!(s, "\u{fffd}");
    }
}
