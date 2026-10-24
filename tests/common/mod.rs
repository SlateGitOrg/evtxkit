//! Shared helpers for integration tests.
#![allow(dead_code, clippy::unwrap_used, missing_docs)]

pub mod builder;
pub mod hostile;

use evtxkit::model::{Element, Node};
use serde_json::{Value as Json, json};
use std::path::PathBuf;

/// Path of a committed sample file.
pub fn sample(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/data")
        .join(name)
}

/// All committed sample names (without extension), sorted.
pub fn sample_names() -> Vec<String> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension()? == "evtx")
                .then(|| p.file_stem().unwrap().to_string_lossy().into_owned())
        })
        .collect();
    names.sort();
    names
}

fn push_text(children: &mut Vec<Json>, text: &str) {
    if let Some(Json::String(prev)) = children.last_mut() {
        prev.push_str(text);
    } else {
        children.push(Json::String(text.to_string()));
    }
}

/// The canonical tree used by golden comparisons (mirrors tools/refdump):
/// element = {"e": name, "a": [[name, value]...], "c": [...]}, text = string,
/// adjacent text merged, whitespace-only text dropped, PIs ignored.
pub fn canonical(el: &Element) -> Json {
    let attrs: Vec<Json> = el
        .attributes
        .iter()
        .map(|a| json!([&*a.name, a.text()]))
        .collect();
    let mut children = Vec::new();
    for n in &el.children {
        match n {
            Node::Element(child) => children.push(canonical(child)),
            Node::ProcessingInstruction { .. } | Node::Substitution(_) => {}
            other => {
                let mut s = String::new();
                other.write_text(&mut s);
                push_text(&mut children, &s);
            }
        }
    }
    children.retain(|c| !matches!(c, Json::String(s) if s.trim().is_empty()));
    json!({"e": &*el.name, "a": attrs, "c": children})
}
