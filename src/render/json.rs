//! JSON rendering of records (one object per line).
//!
//! Mapping from the element tree (documented in `docs/FORMAT.md`):
//!
//! * a leaf element with no attributes becomes a scalar: `null` when empty,
//!   a native number/bool when it holds one typed numeric/bool value, otherwise
//!   its text;
//! * any other element becomes an object: attributes as `"@Name"`, child
//!   elements by name (repeated names collect into an array), and non-blank
//!   text as `"#text"`;
//! * `<Data Name="X">v</Data>` children are keyed by their `Name` attribute
//!   (`"X": v`), which turns `EventData` into a flat object;
//! * `xmlns` attributes are omitted (they are constant and add ~70 bytes/line).
//!
//! The writer emits JSON text directly instead of building a `serde_json::Value`,
//! which avoids one allocation per node on the hot path.

use crate::model::{Element, Node};
use crate::record::{Record, RecordError};
use crate::time::Precision;
use crate::value::Value;
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt::Write as _;

/// Appends `s` as a quoted JSON string.
pub fn write_str(out: &mut String, s: &str) {
    out.reserve(s.len() + 2);
    out.push('"');
    write_escaped(out, s);
    out.push('"');
}

/// Appends the JSON-escaped body of `s` (without quotes).
fn write_escaped(out: &mut String, s: &str) {
    let mut start = 0;
    for (i, c) in s.char_indices() {
        let esc = match c {
            '"' => "\\\"",
            '\\' => "\\\\",
            '\n' => "\\n",
            '\r' => "\\r",
            '\t' => "\\t",
            '\u{08}' => "\\b",
            '\u{0c}' => "\\f",
            c if (c as u32) < 0x20 => "",
            _ => continue,
        };
        out.push_str(&s[start..i]);
        if esc.is_empty() {
            let _ = write!(out, "\\u{:04x}", c as u32);
        } else {
            out.push_str(esc);
        }
        start = i + c.len_utf8();
    }
    out.push_str(&s[start..]);
}

/// Appends a value as a JSON scalar (numbers and bools stay native).
pub fn write_value(out: &mut String, v: &Value) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Int8(n) => push_num(out, n),
        Value::UInt8(n) => push_num(out, n),
        Value::Int16(n) => push_num(out, n),
        Value::UInt16(n) => push_num(out, n),
        Value::Int32(n) => push_num(out, n),
        Value::UInt32(n) => push_num(out, n),
        Value::Int64(n) => push_num(out, n),
        Value::UInt64(n) => push_num(out, n),
        Value::Real32(f) if f.is_finite() => push_num(out, f),
        Value::Real64(f) if f.is_finite() => push_num(out, f),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::String(s) | Value::AnsiString(s) => write_str(out, s),
        other => write_str(out, &other.to_text()),
    }
}

fn push_num(out: &mut String, n: &impl std::fmt::Display) {
    let _ = write!(out, "{n}");
}

fn write_content(out: &mut String, nodes: &[Node]) {
    match nodes {
        [] => out.push_str("null"),
        [Node::Value(v)] => write_value(out, v),
        many => {
            let mut s = String::new();
            for n in many.iter().filter(|n| n.is_text()) {
                n.write_text(&mut s);
            }
            write_str(out, &s);
        }
    }
}

/// Appends the JSON form of `el` (see module docs).
pub fn write_element(out: &mut String, el: &Element) {
    write_element_skipping(out, el, None);
}

/// The JSON key of a child element and whether it was keyed by `@Name`.
fn child_key(child: &Element) -> (Cow<'_, str>, bool) {
    if &*child.name == "Data"
        && let Some(name) = child.attr("Name")
    {
        return (Cow::Owned(name), true);
    }
    (Cow::Borrowed(&*child.name), false)
}

fn keys_unique(keys: &[(Cow<'_, str>, bool, &Element)]) -> bool {
    if keys.len() <= 16 {
        return keys
            .iter()
            .enumerate()
            .all(|(i, (k, _, _))| keys[..i].iter().all(|(o, _, _)| o != k));
    }
    let mut seen = std::collections::HashSet::with_capacity(keys.len());
    keys.iter().all(|(k, _, _)| seen.insert(k.as_ref()))
}

fn write_element_skipping(out: &mut String, el: &Element, skip_attr: Option<&str>) {
    let mut attrs = el
        .attributes
        .iter()
        .filter(|a| &*a.name != "xmlns" && Some(&*a.name) != skip_attr)
        .peekable();
    let has_elements = el.has_element_children();
    if attrs.peek().is_none() && !has_elements {
        write_content(out, &el.children);
        return;
    }
    out.push('{');
    let mut first = true;
    let sep = |out: &mut String, first: &mut bool| {
        if !*first {
            out.push(',');
        }
        *first = false;
    };
    for a in attrs {
        sep(out, &mut first);
        out.push_str("\"@");
        write_escaped(out, &a.name);
        out.push_str("\":");
        write_content(out, &a.value);
    }
    let keys: Vec<(Cow<'_, str>, bool, &Element)> = el
        .child_elements()
        .map(|c| {
            let (k, named) = child_key(c);
            (k, named, c)
        })
        .collect();
    let child_out = |out: &mut String, named: bool, child: &Element| {
        write_element_skipping(out, child, named.then_some("Name"));
    };
    if keys_unique(&keys) {
        // Common case: write children straight into the output.
        for (key, named, child) in &keys {
            sep(out, &mut first);
            write_str(out, key);
            out.push(':');
            child_out(out, *named, child);
        }
    } else {
        // Repeated keys collect into arrays, in first-appearance order.
        let mut groups: Vec<(&str, Vec<(bool, &Element)>)> = Vec::new();
        let mut index: HashMap<&str, usize> = HashMap::new();
        for (key, named, child) in &keys {
            match index.get(key.as_ref()) {
                Some(&i) => groups[i].1.push((*named, child)),
                None => {
                    index.insert(key.as_ref(), groups.len());
                    groups.push((key.as_ref(), vec![(*named, child)]));
                }
            }
        }
        for (key, members) in groups {
            sep(out, &mut first);
            write_str(out, key);
            out.push(':');
            if let [(named, child)] = members.as_slice() {
                child_out(out, *named, child);
            } else {
                out.push('[');
                for (i, (named, child)) in members.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    child_out(out, *named, child);
                }
                out.push(']');
            }
        }
    }
    let mut text = String::new();
    for n in el.children.iter().filter(|n| n.is_text()) {
        n.write_text(&mut text);
    }
    if !text.trim().is_empty() {
        sep(out, &mut first);
        out.push_str("\"#text\":");
        if has_elements {
            write_str(out, &text);
        } else {
            let content: Vec<Node> = el
                .children
                .iter()
                .filter(|n| n.is_text())
                .cloned()
                .collect();
            write_content(out, &content);
        }
    }
    out.push('}');
}

/// One JSONL line for a record: `{"record_id":..,"timestamp":..,"event":{..}}`.
pub fn record_line(r: &Record) -> String {
    let mut out = String::with_capacity(1024);
    write_record(&mut out, r);
    out
}

/// Appends the JSONL object for a record (without the trailing newline).
pub fn write_record(out: &mut String, r: &Record) {
    let _ = write!(out, "{{\"record_id\":{},\"timestamp\":", r.record_id);
    write_str(out, &r.timestamp.to_iso(Precision::Ticks));
    out.push_str(",\"event\":");
    write_element(out, &r.root);
    out.push('}');
}

/// A JSONL line describing a record that failed to decode.
pub fn error_line(e: &RecordError) -> String {
    let mut out = String::with_capacity(160);
    let _ = write!(
        out,
        "{{\"error\":true,\"chunk\":{},\"offset\":{}",
        e.chunk_index, e.file_offset
    );
    if let Some(id) = e.record_id {
        let _ = write!(out, ",\"record_id\":{id}");
    }
    out.push_str(",\"message\":");
    write_str(&mut out, &e.error.to_string());
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Attribute;

    fn leaf(name: &str, v: Value) -> Node {
        let mut e = Element::new(name);
        e.children.push(Node::Value(v));
        Node::Element(e)
    }

    fn attr(name: &str, v: &str) -> Attribute {
        Attribute {
            name: name.into(),
            value: vec![Node::Value(Value::String(v.into()))],
        }
    }

    #[test]
    fn escapes() {
        let mut s = String::new();
        write_str(&mut s, "a\"b\\c\n\r\t\u{8}\u{c}\u{1}é");
        assert_eq!(s, r#""a\"b\\c\n\r\t\b\f\u0001é""#);
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v, "a\"b\\c\n\r\t\u{8}\u{c}\u{1}é");
    }

    #[test]
    fn element_mapping() {
        let mut event = Element::new("Event");
        event.attributes.push(attr("xmlns", "ns"));
        let mut system = Element::new("System");
        let mut prov = Element::new("Provider");
        prov.attributes.push(attr("Name", "P"));
        system.children.push(Node::Element(prov));
        system.children.push(leaf("EventID", Value::UInt16(4624)));
        system
            .children
            .push(Node::Element(Element::new("Correlation")));
        system
            .children
            .push(leaf("Keywords", Value::HexInt64(0x10)));
        let mut eid = Element::new("Level");
        eid.attributes.push(attr("Q", "1"));
        eid.children.push(Node::Value(Value::UInt8(4)));
        system.children.push(Node::Element(eid));
        event.children.push(Node::Element(system));
        let mut ed = Element::new("EventData");
        for (n, v) in [("A", "1"), ("B", "x"), ("A", "2")] {
            let mut d = Element::new("Data");
            d.attributes.push(attr("Name", n));
            d.children.push(Node::Value(Value::String(v.into())));
            ed.children.push(Node::Element(d));
        }
        ed.children
            .push(leaf("Data", Value::String("unnamed".into())));
        event.children.push(Node::Element(ed));
        let mut out = String::new();
        write_element(&mut out, &event);
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(
            v,
            serde_json::json!({
                "System": {
                    "Provider": {"@Name": "P"},
                    "EventID": 4624,
                    "Correlation": null,
                    "Keywords": "0x10",
                    "Level": {"@Q": "1", "#text": 4}
                },
                "EventData": {"A": ["1", "2"], "B": "x", "Data": "unnamed"}
            })
        );
    }

    #[test]
    fn mixed_content_and_non_finite() {
        let mut e = Element::new("M");
        e.children.push(Node::Value(Value::String("a".into())));
        e.children.push(leaf("C", Value::Real64(f64::NAN)));
        e.children.push(Node::CharRef(0x62));
        let mut out = String::new();
        write_element(&mut out, &e);
        assert_eq!(out, r##"{"C":"NaN","#text":"ab"}"##);
        let mut out = String::new();
        write_value(&mut out, &Value::Bool(false));
        write_value(&mut out, &Value::Null);
        write_value(&mut out, &Value::Real32(0.5));
        assert_eq!(out, "falsenull0.5");
    }

    #[test]
    fn error_lines_are_json() {
        let e = RecordError {
            chunk_index: 1,
            file_offset: 99,
            record_id: Some(3),
            error: crate::EvtxError::Io("bad \"x\"".into()),
        };
        let v: serde_json::Value = serde_json::from_str(&error_line(&e)).unwrap();
        assert_eq!(v["record_id"], 3);
        assert_eq!(v["error"], true);
    }
}
