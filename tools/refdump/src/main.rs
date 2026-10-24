//! refdump — emit the reference parser's view of an EVTX file as canonical JSONL.
//!
//! One line per record:
//!   {"record_id": N, "timestamp_ns": "<ns since Unix epoch>", "tree": <node>}
//! or, when the reference parser fails on a record:
//!   {"error": "..."}
//!
//! `<node>` is the canonical tree shared with evtxkit's golden test:
//!   element = {"e": name, "a": [[name, value], ...], "c": [node, ...]}
//!   text    = "string"   (adjacent text merged, whitespace-only text dropped)
//!
//! The canonical form strips formatting differences (indentation, escaping,
//! attribute quoting) so the comparison is about parsed content only.

use quick_xml::events::Event;
use quick_xml::Reader;
use serde_json::{json, Value};
use std::io::{BufWriter, Write};

fn push_text(children: &mut Vec<Value>, text: &str) {
    if let Some(Value::String(prev)) = children.last_mut() {
        prev.push_str(text);
        return;
    }
    children.push(Value::String(text.to_string()));
}

fn finish(children: Vec<Value>) -> Vec<Value> {
    children
        .into_iter()
        .filter(|c| match c {
            Value::String(s) => !s.trim().is_empty(),
            _ => true,
        })
        .collect()
}

fn element(start: &quick_xml::events::BytesStart<'_>) -> (String, Vec<Value>) {
    let name = String::from_utf8_lossy(start.name().as_ref()).into_owned();
    let mut attrs = Vec::new();
    for a in start.attributes().with_checks(false).flatten() {
        let key = String::from_utf8_lossy(a.key.as_ref()).into_owned();
        let val = a
            .unescape_value()
            .map(|v| v.into_owned())
            .unwrap_or_else(|_| String::from_utf8_lossy(&a.value).into_owned());
        attrs.push(json!([key, val]));
    }
    (name, attrs)
}

fn xml_to_tree(xml: &str) -> Result<Value, String> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_end_names = false;
    // Stack of (name, attrs, children).
    let mut stack: Vec<(String, Vec<Value>, Vec<Value>)> = Vec::new();
    let mut root: Option<Value> = None;
    loop {
        match reader.read_event().map_err(|e| e.to_string())? {
            Event::Start(s) => {
                let (n, a) = element(&s);
                stack.push((n, a, Vec::new()));
            }
            Event::Empty(s) => {
                let (n, a) = element(&s);
                let node = json!({"e": n, "a": a, "c": []});
                match stack.last_mut() {
                    Some(top) => top.2.push(node),
                    None => root = Some(node),
                }
            }
            Event::End(_) => {
                let (n, a, c) = stack.pop().ok_or("unbalanced end tag")?;
                let node = json!({"e": n, "a": a, "c": finish(c)});
                match stack.last_mut() {
                    Some(top) => top.2.push(node),
                    None => root = Some(node),
                }
            }
            Event::Text(t) => {
                if let Some(top) = stack.last_mut() {
                    let raw = t.decode().map_err(|e| e.to_string())?;
                    let s = quick_xml::escape::unescape(&raw)
                        .map(|c| c.into_owned())
                        .unwrap_or_else(|_| raw.into_owned());
                    push_text(&mut top.2, &s);
                }
            }
            Event::GeneralRef(r) => {
                if let Some(top) = stack.last_mut() {
                    let name = r.decode().map_err(|e| e.to_string())?;
                    let s = if let Some(ch) = r.resolve_char_ref().ok().flatten() {
                        ch.to_string()
                    } else {
                        match name.as_ref() {
                            "amp" => "&".to_string(),
                            "lt" => "<".to_string(),
                            "gt" => ">".to_string(),
                            "quot" => "\"".to_string(),
                            "apos" => "'".to_string(),
                            other => format!("&{other};"),
                        }
                    };
                    push_text(&mut top.2, &s);
                }
            }
            Event::CData(t) => {
                if let Some(top) = stack.last_mut() {
                    push_text(&mut top.2, &String::from_utf8_lossy(&t));
                }
            }
            Event::Eof => break,
            _ => {}
        }
    }
    root.ok_or_else(|| "no root element".to_string())
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: refdump <file.evtx>");
    let settings = evtx::ParserSettings::new().num_threads(1);
    let mut parser = evtx::EvtxParser::from_path(&path)
        .expect("open")
        .with_configuration(settings);
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    for rec in parser.records() {
        let line = match rec {
            Ok(r) => match xml_to_tree(&r.data) {
                Ok(tree) => json!({
                    "record_id": r.event_record_id,
                    "timestamp_ns": r.timestamp.as_nanosecond().to_string(),
                    "tree": tree,
                }),
                Err(e) => json!({"record_id": r.event_record_id, "error": format!("xml: {e}")}),
            },
            Err(e) => json!({"error": e.to_string()}),
        };
        writeln!(out, "{line}").expect("write");
    }
}
