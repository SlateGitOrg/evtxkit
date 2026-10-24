//! Sigma-style field mapping: logsource tagging plus field renames.
//!
//! A mapping file (YAML, see `mappings/sigma-windows.yml`) describes how raw
//! EVTX fields relate to the Sigma taxonomy:
//!
//! * `services` — Sigma `service` name → EVTX channel;
//! * `rename` — renames applied to every event;
//! * `categories` — ordered rules `(channel, event_ids) → category` with
//!   per-rule renames. The first matching rule wins.
//!
//! Applying a mapping costs O(f + r) per event (f fields, r rules); renames are
//! simultaneous so swaps such as 4688's `ProcessId → ParentProcessId` plus
//! `NewProcessId → ProcessId` behave as written.

use crate::fields::FieldMap;
use crate::render::json::write_str;
use serde::Deserialize;
use std::collections::BTreeMap;
use thiserror::Error;

/// Errors raised while loading a mapping file.
#[derive(Debug, Error)]
pub enum MappingError {
    /// YAML syntax or schema error.
    #[error("mapping is not valid YAML for the expected schema: {0}")]
    Parse(#[from] serde_yaml::Error),
    /// A semantic problem (empty names, unknown references).
    #[error("invalid mapping: {0}")]
    Invalid(String),
    /// The file could not be read.
    #[error("cannot read mapping file: {0}")]
    Io(#[from] std::io::Error),
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMapping {
    name: String,
    #[serde(default = "default_product")]
    product: String,
    #[serde(default)]
    services: BTreeMap<String, String>,
    #[serde(default)]
    rename: BTreeMap<String, String>,
    #[serde(default)]
    categories: Vec<RawRule>,
}

fn default_product() -> String {
    "windows".to_string()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRule {
    category: String,
    channel: String,
    event_ids: Vec<u32>,
    #[serde(default)]
    rename: BTreeMap<String, String>,
}

/// One category rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CategoryRule {
    /// Sigma category assigned on match.
    pub category: String,
    /// Channel the event must come from (case-insensitive).
    pub channel: String,
    /// Event IDs that match.
    pub event_ids: Vec<u32>,
    /// Field renames applied on match.
    pub rename: Vec<(String, String)>,
}

/// A validated mapping.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mapping {
    /// Mapping name.
    pub name: String,
    /// Sigma product (normally `windows`).
    pub product: String,
    /// (service, channel) pairs.
    pub services: Vec<(String, String)>,
    /// Global renames.
    pub rename: Vec<(String, String)>,
    /// Category rules in priority order.
    pub rules: Vec<CategoryRule>,
}

/// The Sigma logsource an event was tagged with.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogSource {
    /// Product (from the mapping).
    pub product: String,
    /// Service whose channel matched.
    pub service: Option<String>,
    /// Category of the first matching rule.
    pub category: Option<String>,
}

impl LogSource {
    /// The logsource as a compact JSON object.
    pub fn to_json(&self) -> String {
        let mut out = String::from("{\"product\":");
        write_str(&mut out, &self.product);
        for (key, val) in [("service", &self.service), ("category", &self.category)] {
            if let Some(v) = val {
                out.push_str(",\"");
                out.push_str(key);
                out.push_str("\":");
                write_str(&mut out, v);
            }
        }
        out.push('}');
        out
    }
}

const BUILTIN: &str = include_str!("../mappings/sigma-windows.yml");

fn pairs(map: BTreeMap<String, String>, what: &str) -> Result<Vec<(String, String)>, MappingError> {
    map.into_iter()
        .map(|(k, v)| {
            if k.trim().is_empty() || v.trim().is_empty() {
                Err(MappingError::Invalid(format!("empty name in {what}")))
            } else {
                Ok((k, v))
            }
        })
        .collect()
}

impl Mapping {
    /// Parses and validates a mapping from YAML text.
    pub fn from_yaml(text: &str) -> Result<Self, MappingError> {
        let raw: RawMapping = serde_yaml::from_str(text)?;
        if raw.name.trim().is_empty() {
            return Err(MappingError::Invalid("mapping name is empty".into()));
        }
        let services = pairs(raw.services, "services")?;
        let rename = pairs(raw.rename, "rename")?;
        let mut rules = Vec::with_capacity(raw.categories.len());
        for (i, r) in raw.categories.into_iter().enumerate() {
            if r.category.trim().is_empty() || r.channel.trim().is_empty() {
                return Err(MappingError::Invalid(format!(
                    "category rule #{} needs a category and a channel",
                    i + 1
                )));
            }
            if r.event_ids.is_empty() {
                return Err(MappingError::Invalid(format!(
                    "category rule #{} ({}) lists no event_ids",
                    i + 1,
                    r.category
                )));
            }
            rules.push(CategoryRule {
                category: r.category,
                channel: r.channel,
                event_ids: r.event_ids,
                rename: pairs(r.rename, "category rename")?,
            });
        }
        Ok(Mapping {
            name: raw.name,
            product: raw.product,
            services,
            rename,
            rules,
        })
    }

    /// Loads a mapping file.
    pub fn from_path(path: &std::path::Path) -> Result<Self, MappingError> {
        Self::from_yaml(&std::fs::read_to_string(path)?)
    }

    /// The built-in `sigma-windows` mapping.
    pub fn builtin() -> Self {
        // The embedded file is validated by a unit test; failing here would be a build defect.
        Self::from_yaml(BUILTIN).unwrap_or_else(|e| panic!("built-in mapping is invalid: {e}"))
    }

    /// Tags `fields` with a logsource and applies renames in place.
    pub fn apply(&self, fields: &mut FieldMap) -> LogSource {
        let channel = fields.get("Channel").unwrap_or_default().to_string();
        let event_id: Option<u32> = fields.get("EventID").and_then(|v| v.trim().parse().ok());
        let service = self
            .services
            .iter()
            .find(|(_, ch)| ch.eq_ignore_ascii_case(&channel))
            .map(|(s, _)| s.clone());
        fields.rename_all(&self.rename);
        let rule = event_id.and_then(|id| {
            self.rules
                .iter()
                .find(|r| r.channel.eq_ignore_ascii_case(&channel) && r.event_ids.contains(&id))
        });
        if let Some(r) = rule {
            fields.rename_all(&r.rename);
        }
        LogSource {
            product: self.product.clone(),
            service,
            category: rule.map(|r| r.category.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_is_valid_and_maps_4688() {
        let m = Mapping::builtin();
        assert_eq!(m.name, "sigma-windows");
        let mut f = FieldMap::new();
        f.insert("Channel", "Security");
        f.insert("EventID", "4688");
        f.insert("NewProcessName", "C:\\Windows\\System32\\cmd.exe");
        f.insert("ProcessId", "0x10");
        f.insert("NewProcessId", "0x20");
        let ls = m.apply(&mut f);
        assert_eq!(ls.category.as_deref(), Some("process_creation"));
        assert_eq!(ls.service.as_deref(), Some("security"));
        assert_eq!(f.get("Image"), Some("C:\\Windows\\System32\\cmd.exe"));
        assert_eq!(f.get("ParentProcessId"), Some("0x10"));
        assert_eq!(f.get("ProcessId"), Some("0x20"));
        assert_eq!(
            ls.to_json(),
            r#"{"product":"windows","service":"security","category":"process_creation"}"#
        );
    }

    #[test]
    fn unmatched_events_keep_fields() {
        let m = Mapping::builtin();
        let mut f = FieldMap::new();
        f.insert("Channel", "Custom/Log");
        f.insert("EventID", "x");
        let ls = m.apply(&mut f);
        assert_eq!(
            ls,
            LogSource {
                product: "windows".into(),
                service: None,
                category: None
            }
        );
        assert_eq!(ls.to_json(), r#"{"product":"windows"}"#);
    }

    #[test]
    fn validation_errors() {
        assert!(matches!(
            Mapping::from_yaml("name: ''"),
            Err(MappingError::Invalid(_))
        ));
        assert!(matches!(
            Mapping::from_yaml("nme: x"),
            Err(MappingError::Parse(_))
        ));
        let no_ids = "name: x\ncategories:\n  - {category: c, channel: S, event_ids: []}\n";
        assert!(matches!(
            Mapping::from_yaml(no_ids),
            Err(MappingError::Invalid(_))
        ));
        let no_chan = "name: x\ncategories:\n  - {category: c, channel: ' ', event_ids: [1]}\n";
        assert!(Mapping::from_yaml(no_chan).is_err());
        let bad_rename = "name: x\nrename: {A: ''}\n";
        assert!(Mapping::from_yaml(bad_rename).is_err());
        let ok = "name: x\nproduct: linux\nrename: {A: B}\n";
        let m = Mapping::from_yaml(ok).unwrap();
        assert_eq!(m.product, "linux");
        let mut f = FieldMap::new();
        f.insert("A", "1");
        m.apply(&mut f);
        assert_eq!(f.get("B"), Some("1"));
        assert!(Mapping::from_path(std::path::Path::new("/nonexistent/x.yml")).is_err());
    }
}
