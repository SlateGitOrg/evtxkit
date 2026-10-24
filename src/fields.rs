//! A flat `name → value` view of a record, the shape detection rules expect.
//!
//! Flattening rules (documented in `docs/FORMAT.md`):
//!
//! * `System/X` with text → `X`; its attributes → `X_Attr`
//!   (`Provider_Name`, `TimeCreated_SystemTime`, `Execution_ProcessID`, ...);
//! * `EventData/Data[@Name=N]` → `N`; unnamed `Data` → `Data_1`, `Data_2`, ...;
//!   other `EventData` children (e.g. `Binary`) → their element name;
//! * `UserData` subtrees → leaf element names (attributes as `Leaf_Attr`);
//! * any other top-level section `S` → `S_Leaf` (e.g. `RenderingInfo_Message`).
//!
//! Duplicate names are kept; filters match if *any* value matches.

use crate::model::{Element, Node};
use crate::record::Record;
use crate::render::json::write_str;
use std::fmt::Write as _;

/// Ordered multimap of field names to text values.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FieldMap {
    entries: Vec<(String, String)>,
}

impl FieldMap {
    /// Empty map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a field (duplicates allowed).
    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.entries.push((name.into(), value.into()));
    }

    /// First value of `name`: exact match first, then ASCII case-insensitive.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k == name)
            .or_else(|| {
                self.entries
                    .iter()
                    .find(|(k, _)| k.eq_ignore_ascii_case(name))
            })
            .map(|(_, v)| v.as_str())
    }

    /// Every value of `name` (case-insensitive).
    pub fn get_all<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.entries
            .iter()
            .filter(move |(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// All entries in insertion order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Renames fields simultaneously: each entry is looked up once, so
    /// `{A→B, B→A}` swaps rather than collapsing.
    pub fn rename_all(&mut self, renames: &[(String, String)]) {
        if renames.is_empty() {
            return;
        }
        for (k, _) in &mut self.entries {
            if let Some((_, to)) = renames.iter().find(|(from, _)| from == k) {
                k.clone_from(to);
            }
        }
    }

    /// Appends the map as a JSON object; repeated names become arrays.
    pub fn write_json(&self, out: &mut String) {
        out.push('{');
        let mut done = vec![false; self.entries.len()];
        let mut first = true;
        for i in 0..self.entries.len() {
            if done[i] {
                continue;
            }
            let key = &self.entries[i].0;
            let same: Vec<usize> = (i..self.entries.len())
                .filter(|&j| !done[j] && self.entries[j].0 == *key)
                .collect();
            if !first {
                out.push(',');
            }
            first = false;
            write_str(out, key);
            out.push(':');
            if let [only] = same.as_slice() {
                write_str(out, &self.entries[*only].1);
            } else {
                out.push('[');
                for (n, &j) in same.iter().enumerate() {
                    if n > 0 {
                        out.push(',');
                    }
                    write_str(out, &self.entries[j].1);
                }
                out.push(']');
            }
            for j in same {
                done[j] = true;
            }
        }
        out.push('}');
    }
}

fn flatten_generic(prefix: &str, el: &Element, out: &mut FieldMap) {
    let base = if prefix.is_empty() {
        el.name.to_string()
    } else {
        format!("{prefix}_{}", el.name)
    };
    for a in &el.attributes {
        if &*a.name != "xmlns" {
            out.insert(format!("{base}_{}", a.name), a.text());
        }
    }
    if el.has_element_children() {
        for child in el.child_elements() {
            flatten_generic(prefix, child, out);
        }
    } else if el.children.iter().any(Node::is_text) {
        out.insert(base, el.text());
    }
}

/// Builds the flat field view of a record.
pub fn flatten(record: &Record) -> FieldMap {
    let mut out = FieldMap::new();
    for section in record.root.child_elements() {
        match &*section.name {
            "System" => {
                for el in section.child_elements() {
                    let text = el.text();
                    if !text.is_empty() {
                        out.insert(el.name.to_string(), text);
                    }
                    for a in &el.attributes {
                        out.insert(format!("{}_{}", el.name, a.name), a.text());
                    }
                }
            }
            "EventData" => {
                let mut unnamed = 0;
                for el in section.child_elements() {
                    match (&*el.name, el.attr("Name")) {
                        ("Data", Some(name)) => out.insert(name, el.text()),
                        ("Data", None) => {
                            unnamed += 1;
                            out.insert(format!("Data_{unnamed}"), el.text());
                        }
                        _ => flatten_generic("", el, &mut out),
                    }
                }
            }
            "UserData" => {
                for el in section.child_elements() {
                    // The wrapper element (e.g. <LogFileCleared>) carries no data itself.
                    for leaf in el.child_elements() {
                        flatten_generic("", leaf, &mut out);
                    }
                    for a in el.attributes.iter().filter(|a| &*a.name != "xmlns") {
                        out.insert(format!("{}_{}", el.name, a.name), a.text());
                    }
                }
            }
            other => {
                for el in section.child_elements() {
                    flatten_generic(other, el, &mut out);
                }
            }
        }
    }
    out
}

/// One JSONL line: `{"_record_id":..,"_timestamp":..,<fields>}` plus an
/// optional `_logsource` object.
pub fn record_line(record: &Record, fields: &FieldMap, logsource: Option<&str>) -> String {
    let mut out = String::with_capacity(512);
    let _ = write!(out, "{{\"_record_id\":{},\"_timestamp\":", record.record_id);
    write_str(
        &mut out,
        &record.timestamp.to_iso(crate::time::Precision::Ticks),
    );
    if let Some(ls) = logsource {
        out.push_str(",\"_logsource\":");
        out.push_str(ls);
    }
    out.push_str(",\"fields\":");
    fields.write_json(&mut out);
    out.push('}');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Attribute;
    use crate::time::FileTime;
    use crate::value::Value;

    fn el(name: &str, text: Option<&str>, attrs: &[(&str, &str)], kids: Vec<Element>) -> Element {
        let mut e = Element::new(name);
        for (k, v) in attrs {
            e.attributes.push(Attribute {
                name: (*k).into(),
                value: vec![Node::Value(Value::String((*v).into()))],
            });
        }
        if let Some(t) = text {
            e.children.push(Node::Value(Value::String(t.into())));
        }
        e.children.extend(kids.into_iter().map(Node::Element));
        e
    }

    fn record(root: Element) -> Record {
        Record {
            chunk_index: 0,
            file_offset: 0,
            record_id: 7,
            timestamp: FileTime(116_444_736_000_000_000),
            size_copy_valid: true,
            recovered: false,
            root,
        }
    }

    #[test]
    fn flattens_all_sections() {
        let root = el(
            "Event",
            None,
            &[("xmlns", "ns")],
            vec![
                el(
                    "System",
                    None,
                    &[],
                    vec![
                        el("Provider", None, &[("Name", "P")], vec![]),
                        el("EventID", Some("4688"), &[("Qualifiers", "0")], vec![]),
                        el("Correlation", None, &[], vec![]),
                    ],
                ),
                el(
                    "EventData",
                    None,
                    &[],
                    vec![
                        el(
                            "Data",
                            Some("C:\\x.exe"),
                            &[("Name", "NewProcessName")],
                            vec![],
                        ),
                        el("Data", Some("a"), &[], vec![]),
                        el("Data", Some("b"), &[], vec![]),
                        el("Binary", Some("00FF"), &[], vec![]),
                    ],
                ),
                el(
                    "UserData",
                    None,
                    &[],
                    vec![el(
                        "LogFileCleared",
                        None,
                        &[("xmlns", "x"), ("v", "1")],
                        vec![el("SubjectUserName", Some("bob"), &[], vec![])],
                    )],
                ),
                el(
                    "RenderingInfo",
                    None,
                    &[("Culture", "en-US")],
                    vec![el("Message", Some("hi"), &[], vec![])],
                ),
            ],
        );
        let f = flatten(&record(root));
        let got: Vec<(&str, &str)> = f.iter().collect();
        assert_eq!(
            got,
            vec![
                ("Provider_Name", "P"),
                ("EventID", "4688"),
                ("EventID_Qualifiers", "0"),
                ("NewProcessName", "C:\\x.exe"),
                ("Data_1", "a"),
                ("Data_2", "b"),
                ("Binary", "00FF"),
                ("SubjectUserName", "bob"),
                ("LogFileCleared_v", "1"),
                ("RenderingInfo_Message", "hi"),
            ]
        );
        assert_eq!(f.get("eventid"), Some("4688"));
        assert_eq!(f.get("nope"), None);
        assert_eq!(f.len(), 10);
        assert!(!f.is_empty());
    }

    #[test]
    fn rename_is_simultaneous_and_json_groups_duplicates() {
        let mut f = FieldMap::new();
        f.insert("A", "1");
        f.insert("B", "2");
        f.insert("A", "3");
        f.rename_all(&[("A".into(), "B".into()), ("B".into(), "A".into())]);
        assert_eq!(f.get_all("B").collect::<Vec<_>>(), vec!["1", "3"]);
        assert_eq!(f.get("A"), Some("2"));
        let mut s = String::new();
        f.write_json(&mut s);
        assert_eq!(s, r#"{"B":["1","3"],"A":"2"}"#);
        let line = record_line(&record(Element::new("Event")), &f, Some("{}"));
        let v: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(v["_record_id"], 7);
        assert_eq!(v["_timestamp"], "1970-01-01T00:00:00.0000000Z");
        assert_eq!(v["fields"]["A"], "2");
    }
}
