//! XML rendering, close to what Windows Event Viewer shows.

use crate::model::{Element, Node};
use crate::record::Record;
use std::fmt::Write as _;

fn escape_into(out: &mut String, s: &str, attribute: bool) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if attribute => out.push_str("&quot;"),
            c => out.push(c),
        }
    }
}

fn write_node(out: &mut String, node: &Node, attribute: bool) {
    match node {
        Node::Value(v) => escape_into(out, &v.to_text(), attribute),
        Node::CharRef(c) => {
            let _ = write!(out, "&#{c};");
        }
        Node::EntityRef(name) => {
            let _ = write!(out, "&{name};");
        }
        Node::CData(s) => {
            if attribute {
                escape_into(out, s, true);
            } else {
                // A literal "]]>" cannot appear inside CDATA; split it.
                out.push_str("<![CDATA[");
                out.push_str(&s.replace("]]>", "]]]]><![CDATA[>"));
                out.push_str("]]>");
            }
        }
        Node::ProcessingInstruction { target, data } if !attribute => {
            let _ = write!(out, "<?{target} {data}?>");
        }
        Node::Element(e) if !attribute => write_element(out, e, None),
        _ => {}
    }
}

/// Appends `el` as XML. With `indent = Some(level)`, elements that contain only
/// elements are pretty-printed with two spaces per level.
pub fn write_element(out: &mut String, el: &Element, indent: Option<usize>) {
    let pad = |out: &mut String, level: usize| {
        for _ in 0..level {
            out.push_str("  ");
        }
    };
    if let Some(level) = indent {
        pad(out, level);
    }
    out.push('<');
    out.push_str(&el.name);
    for a in &el.attributes {
        out.push(' ');
        out.push_str(&a.name);
        out.push_str("=\"");
        for n in &a.value {
            write_node(out, n, true);
        }
        out.push('"');
    }
    if el.children.is_empty() {
        out.push_str("/>");
    } else {
        out.push('>');
        let only_elements = el.children.iter().all(|n| matches!(n, Node::Element(_)));
        match indent {
            Some(level) if only_elements => {
                for n in &el.children {
                    out.push('\n');
                    if let Node::Element(child) = n {
                        write_element(out, child, Some(level + 1));
                    }
                }
                out.push('\n');
                pad(out, level);
            }
            _ => {
                for n in &el.children {
                    write_node(out, n, false);
                }
            }
        }
        out.push_str("</");
        out.push_str(&el.name);
        out.push('>');
    }
}

/// The XML document for one record (declaration + pretty-printed `<Event>`).
pub fn record_document(r: &Record) -> String {
    let mut out = String::with_capacity(2048);
    out.push_str("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n");
    write_element(&mut out, &r.root, Some(0));
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Attribute;
    use crate::value::Value;

    #[test]
    fn renders_and_escapes() {
        let mut e = Element::new("Event");
        e.attributes.push(Attribute {
            name: "a".into(),
            value: vec![
                Node::Value(Value::String("x\"<&".into())),
                Node::CData("c".into()),
                Node::Element(Element::new("ignored")),
            ],
        });
        let mut d = Element::new("Data");
        d.children.extend([
            Node::Value(Value::String("1 < 2".into())),
            Node::CharRef(65),
            Node::EntityRef("amp".into()),
            Node::CData("a]]>b".into()),
            Node::ProcessingInstruction {
                target: "pi".into(),
                data: "d".into(),
            },
        ]);
        e.children.push(Node::Element(d));
        e.children.push(Node::Element(Element::new("Empty")));
        let mut out = String::new();
        write_element(&mut out, &e, Some(0));
        assert_eq!(
            out,
            "<Event a=\"x&quot;&lt;&amp;c\">\n  <Data>1 &lt; 2&#65;&amp;<![CDATA[a]]]]><![CDATA[>b]]><?pi d?></Data>\n  <Empty/>\n</Event>"
        );
        let mut flat = String::new();
        write_element(&mut flat, &e, None);
        assert!(flat.starts_with("<Event a=") && !flat.contains('\n'));
    }
}
