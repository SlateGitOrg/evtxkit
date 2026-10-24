//! Mergeable statistics over files, chunks and records.
//!
//! Each worker builds a [`Stats`] for its chunk; the sink merges them in file
//! order, so aggregation is parallel and the result is deterministic.

use crate::chunk::CrcStatus;
use crate::fields::FieldMap;
use crate::pipeline::{SlotInfo, SlotKind};
use crate::record::{Record, RecordError};
use crate::time::{FileTime, Precision};
use serde_json::{Value as Json, json};
use std::collections::HashMap;
use std::fmt::Write as _;

/// Frequency counter with deterministic top-N output.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Counter {
    counts: HashMap<String, u64>,
}

impl Counter {
    /// Counts one occurrence of `key`.
    pub fn add(&mut self, key: &str) {
        *self.counts.entry(key.to_string()).or_default() += 1;
    }

    /// Adds every count of `other`.
    pub fn merge(&mut self, other: &Counter) {
        for (k, v) in &other.counts {
            *self.counts.entry(k.clone()).or_default() += v;
        }
    }

    /// Number of distinct keys.
    pub fn distinct(&self) -> usize {
        self.counts.len()
    }

    /// The `n` most frequent keys (ties broken by key, ascending).
    pub fn top(&self, n: usize) -> Vec<(&str, u64)> {
        let mut v: Vec<(&str, u64)> = self.counts.iter().map(|(k, c)| (k.as_str(), *c)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        v.truncate(n);
        v
    }
}

/// Aggregate statistics.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Stats {
    /// Chunk slots seen.
    pub slots: usize,
    /// Slots with a valid chunk signature.
    pub chunks: usize,
    /// All-zero slots.
    pub empty_slots: usize,
    /// Undecodable slots.
    pub corrupt_slots: usize,
    /// Chunks skipped because of CRC policy.
    pub skipped_chunks: usize,
    /// Chunk header CRC mismatches.
    pub header_crc_mismatches: usize,
    /// Record-area CRC mismatches.
    pub records_crc_mismatches: usize,
    /// Chunks whose flags disable CRCs.
    pub crc_disabled_chunks: usize,
    /// Template definitions decoded.
    pub templates: usize,
    /// Records decoded.
    pub records: u64,
    /// Records found by resynchronisation.
    pub recovered_records: u64,
    /// Records whose trailing size copy disagreed.
    pub size_copy_mismatches: u64,
    /// Record-level errors (excluding corrupt/skipped slot entries).
    pub record_errors: u64,
    /// Smallest record id.
    pub min_record_id: Option<u64>,
    /// Largest record id.
    pub max_record_id: Option<u64>,
    /// Earliest record timestamp.
    pub first_timestamp: Option<FileTime>,
    /// Latest record timestamp.
    pub last_timestamp: Option<FileTime>,
    /// Records per EventID.
    pub event_ids: Counter,
    /// Records per provider name.
    pub providers: Counter,
    /// Records per channel.
    pub channels: Counter,
    /// Records per computer.
    pub computers: Counter,
    /// Records per value of a user-chosen field (`--by`).
    pub group: Counter,
}

fn min_opt<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) | (None, x) => x,
    }
}

fn max_opt<T: Ord + Copy>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.max(y)),
        (x, None) | (None, x) => x,
    }
}

impl Stats {
    /// Accounts for one slot summary.
    pub fn add_slot(&mut self, info: &SlotInfo) {
        self.slots += 1;
        match info.kind {
            SlotKind::Empty => self.empty_slots += 1,
            SlotKind::Corrupt => self.corrupt_slots += 1,
            SlotKind::Chunk => {
                self.chunks += 1;
                self.templates += info.templates;
                if info.skipped {
                    self.skipped_chunks += 1;
                }
                for crc in [info.header_crc, info.records_crc].into_iter().flatten() {
                    if crc == CrcStatus::Disabled {
                        self.crc_disabled_chunks += 1;
                        break;
                    }
                }
                if matches!(info.header_crc, Some(CrcStatus::Mismatch { .. })) {
                    self.header_crc_mismatches += 1;
                }
                if matches!(info.records_crc, Some(CrcStatus::Mismatch { .. })) {
                    self.records_crc_mismatches += 1;
                }
            }
        }
    }

    /// Accounts for one decoded record; `group` is the `--by` value, if any.
    pub fn add_record(&mut self, r: &Record, group: Option<&str>) {
        self.records += 1;
        self.recovered_records += u64::from(r.recovered);
        self.size_copy_mismatches += u64::from(!r.size_copy_valid);
        self.min_record_id = min_opt(self.min_record_id, Some(r.record_id));
        self.max_record_id = max_opt(self.max_record_id, Some(r.record_id));
        self.first_timestamp = min_opt(self.first_timestamp, Some(r.timestamp));
        self.last_timestamp = max_opt(self.last_timestamp, Some(r.timestamp));
        if let Some(system) = r.root.child("System") {
            let text = |name: &str| system.child(name).map(|e| e.text()).unwrap_or_default();
            self.event_ids.add(&text("EventID"));
            self.channels.add(&text("Channel"));
            self.computers.add(&text("Computer"));
            let provider = system
                .child("Provider")
                .and_then(|p| p.attr("Name"))
                .unwrap_or_default();
            self.providers.add(&provider);
        }
        if let Some(g) = group {
            self.group.add(g);
        }
    }

    /// Accounts for a record-level error.
    pub fn add_error(&mut self, _e: &RecordError, from_slot: bool) {
        if !from_slot {
            self.record_errors += 1;
        }
    }

    /// Group value for `field` from a field map (missing → `(missing)`).
    pub fn group_value(fields: &FieldMap, field: &str) -> String {
        fields.get(field).unwrap_or("(missing)").to_string()
    }

    /// Merges `other` into `self`.
    pub fn merge(&mut self, o: &Stats) {
        self.slots += o.slots;
        self.chunks += o.chunks;
        self.empty_slots += o.empty_slots;
        self.corrupt_slots += o.corrupt_slots;
        self.skipped_chunks += o.skipped_chunks;
        self.header_crc_mismatches += o.header_crc_mismatches;
        self.records_crc_mismatches += o.records_crc_mismatches;
        self.crc_disabled_chunks += o.crc_disabled_chunks;
        self.templates += o.templates;
        self.records += o.records;
        self.recovered_records += o.recovered_records;
        self.size_copy_mismatches += o.size_copy_mismatches;
        self.record_errors += o.record_errors;
        self.min_record_id = min_opt(self.min_record_id, o.min_record_id);
        self.max_record_id = max_opt(self.max_record_id, o.max_record_id);
        self.first_timestamp = min_opt(self.first_timestamp, o.first_timestamp);
        self.last_timestamp = max_opt(self.last_timestamp, o.last_timestamp);
        self.event_ids.merge(&o.event_ids);
        self.providers.merge(&o.providers);
        self.channels.merge(&o.channels);
        self.computers.merge(&o.computers);
        self.group.merge(&o.group);
    }

    fn top_json(c: &Counter, n: usize) -> Json {
        Json::Array(
            c.top(n)
                .into_iter()
                .map(|(k, v)| json!({"value": k, "count": v}))
                .collect(),
        )
    }

    /// Machine-readable form; `group_by` names the `--by` field.
    pub fn to_json(&self, top: usize, group_by: Option<&str>) -> Json {
        let ts = |t: Option<FileTime>| t.map(|t| t.to_iso(Precision::Ticks));
        let mut v = json!({
            "slots": self.slots,
            "chunks": self.chunks,
            "empty_slots": self.empty_slots,
            "corrupt_slots": self.corrupt_slots,
            "skipped_chunks": self.skipped_chunks,
            "crc": {
                "header_mismatches": self.header_crc_mismatches,
                "records_mismatches": self.records_crc_mismatches,
                "disabled_chunks": self.crc_disabled_chunks,
            },
            "templates": self.templates,
            "records": self.records,
            "recovered_records": self.recovered_records,
            "size_copy_mismatches": self.size_copy_mismatches,
            "record_errors": self.record_errors,
            "record_id_range": [self.min_record_id, self.max_record_id],
            "time_range": [ts(self.first_timestamp), ts(self.last_timestamp)],
            "event_ids": Self::top_json(&self.event_ids, top),
            "providers": Self::top_json(&self.providers, top),
            "channels": Self::top_json(&self.channels, top),
            "computers": Self::top_json(&self.computers, top),
        });
        if let Some(field) = group_by {
            v["group_by"] = json!({"field": field, "top": Self::top_json(&self.group, top)});
        }
        v
    }

    /// Human-readable report.
    pub fn render_text(&self, top: usize, group_by: Option<&str>) -> String {
        let mut s = String::new();
        let ts = |t: Option<FileTime>| t.map_or("-".to_string(), |t| t.to_iso(Precision::Micros));
        let id = |v: Option<u64>| v.map_or("-".to_string(), |v| v.to_string());
        let _ = writeln!(
            s,
            "  slots      {} ({} chunks, {} empty, {} corrupt, {} skipped)",
            self.slots, self.chunks, self.empty_slots, self.corrupt_slots, self.skipped_chunks
        );
        let _ = writeln!(
            s,
            "  crc32      header mismatches {}, record-data mismatches {}, disabled {}",
            self.header_crc_mismatches, self.records_crc_mismatches, self.crc_disabled_chunks
        );
        let _ = writeln!(
            s,
            "  records    {} decoded, {} errors, {} recovered, {} size-copy mismatches",
            self.records, self.record_errors, self.recovered_records, self.size_copy_mismatches
        );
        let _ = writeln!(s, "  templates  {}", self.templates);
        let _ = writeln!(
            s,
            "  ids        {} .. {}",
            id(self.min_record_id),
            id(self.max_record_id)
        );
        let _ = writeln!(
            s,
            "  time       {} .. {}",
            ts(self.first_timestamp),
            ts(self.last_timestamp)
        );
        let mut section = |title: &str, c: &Counter| {
            if c.distinct() == 0 {
                return;
            }
            let items: Vec<String> = c
                .top(top)
                .iter()
                .map(|(k, v)| format!("{k} ({v})"))
                .collect();
            let _ = writeln!(s, "  {title:<10} {}", items.join(", "));
        };
        section("event ids", &self.event_ids);
        section("providers", &self.providers);
        section("channels", &self.channels);
        section("computers", &self.computers);
        if let Some(field) = group_by {
            section(&format!("by {field}"), &self.group);
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_top_is_deterministic() {
        let mut c = Counter::default();
        for k in ["b", "a", "b", "c", "a", "d"] {
            c.add(k);
        }
        assert_eq!(c.top(3), vec![("a", 2), ("b", 2), ("c", 1)]);
        let mut d = Counter::default();
        d.add("c");
        d.add("c");
        d.merge(&c);
        assert_eq!(d.top(1), vec![("c", 3)]);
        assert_eq!(d.distinct(), 4);
    }

    #[test]
    fn merge_combines_ranges() {
        let mut a = Stats {
            min_record_id: Some(5),
            max_record_id: Some(9),
            ..Stats::default()
        };
        let b = Stats {
            min_record_id: Some(2),
            max_record_id: None,
            records: 3,
            ..Stats::default()
        };
        a.merge(&b);
        assert_eq!(
            (a.min_record_id, a.max_record_id, a.records),
            (Some(2), Some(9), 3)
        );
        let j = a.to_json(5, Some("X"));
        assert_eq!(j["record_id_range"], json!([2, 9]));
        assert_eq!(j["group_by"]["field"], "X");
        assert!(a.render_text(5, Some("X")).contains("2 .. 9"));
        let mut f = FieldMap::new();
        f.insert("X", "1");
        assert_eq!(Stats::group_value(&f, "X"), "1");
        assert_eq!(Stats::group_value(&f, "Y"), "(missing)");
    }
}
