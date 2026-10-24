//! Field filter expressions for `dump -w` / `grep -w`.
//!
//! Grammar (one expression per `-w`, all expressions ANDed):
//!
//! ```text
//! expr     := field ( "|" modifier )* op value
//! op       := "=" | "!=" | ">" | ">=" | "<" | "<="
//! modifier := contains | startswith | endswith | re | in | cased | exists
//! ```
//!
//! Semantics follow Sigma: string comparison is case-insensitive unless
//! `|cased` is given; a plain `=` value may use `*` and `?` wildcards (a
//! backslash escapes `*`, `?` and `\` and is literal otherwise, as in Sigma);
//! `|in` splits the value on commas and matches any item; `|exists`
//! takes `true`/`false`. Ordering operators compare numerically (decimal or
//! `0x` hex) and ignore non-numeric values. A field with several values
//! matches if any value matches; `!=` is the negation of `=`.
//!
//! Matching cost: contains/starts/ends O(n); wildcard globs O(n·m) worst case
//! with the two-pointer backtracking algorithm; regexes use the `regex` crate,
//! which guarantees linear time in the input.

use crate::fields::FieldMap;
use regex::{Regex, RegexBuilder};
use thiserror::Error;

/// A malformed filter expression.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid filter `{expr}`: {reason}")]
pub struct FilterError {
    /// The expression as given.
    pub expr: String,
    /// What is wrong.
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmp {
    Gt,
    Ge,
    Lt,
    Le,
}

#[derive(Debug, Clone)]
enum Matcher {
    Glob(Vec<GlobTok>),
    Contains(String),
    StartsWith(String),
    EndsWith(String),
    Regex(Regex),
    Number(Cmp, f64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GlobTok {
    Char(char),
    Any,
    Star,
}

/// One compiled `field|mods op value` expression.
#[derive(Debug, Clone)]
pub struct Filter {
    field: String,
    negate: bool,
    cased: bool,
    exists: Option<bool>,
    alternatives: Vec<Matcher>,
}

fn parse_glob(pattern: &str) -> Vec<GlobTok> {
    let mut out = Vec::with_capacity(pattern.len());
    let mut chars = pattern.chars().peekable();
    while let Some(c) = chars.next() {
        out.push(match c {
            // Sigma escaping: `\` only escapes `*`, `?` and itself; any other
            // backslash is literal, so Windows paths need no doubling.
            '\\' => match chars.peek() {
                Some(&n @ ('*' | '?' | '\\')) => {
                    chars.next();
                    GlobTok::Char(n)
                }
                _ => GlobTok::Char('\\'),
            },
            '*' => GlobTok::Star,
            '?' => GlobTok::Any,
            c => GlobTok::Char(c),
        });
    }
    out
}

/// Wildcard match with greedy star backtracking (classic two-pointer algorithm).
fn glob_match(pattern: &[GlobTok], text: &[char]) -> bool {
    let (mut p, mut t) = (0, 0);
    let mut star: Option<(usize, usize)> = None;
    while t < text.len() {
        match pattern.get(p) {
            Some(GlobTok::Char(c)) if *c == text[t] => {
                p += 1;
                t += 1;
            }
            Some(GlobTok::Any) => {
                p += 1;
                t += 1;
            }
            Some(GlobTok::Star) => {
                star = Some((p, t));
                p += 1;
            }
            _ => match star {
                Some((sp, st)) => {
                    p = sp + 1;
                    t = st + 1;
                    star = Some((sp, st + 1));
                }
                None => return false,
            },
        }
    }
    pattern[p..].iter().all(|tok| *tok == GlobTok::Star)
}

/// Parses `123`, `-4.5` or `0x1F` as a number.
pub fn parse_number(s: &str) -> Option<f64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u64::from_str_radix(hex, 16).ok().map(|v| v as f64);
    }
    s.parse::<f64>().ok().filter(|v| v.is_finite())
}

fn fold(s: &str, cased: bool) -> String {
    if cased {
        s.to_string()
    } else {
        s.to_lowercase()
    }
}

impl Matcher {
    fn matches(&self, value: &str, cased: bool) -> bool {
        match self {
            Matcher::Glob(p) => {
                let text: Vec<char> = fold(value, cased).chars().collect();
                glob_match(p, &text)
            }
            Matcher::Contains(s) => fold(value, cased).contains(s.as_str()),
            Matcher::StartsWith(s) => fold(value, cased).starts_with(s.as_str()),
            Matcher::EndsWith(s) => fold(value, cased).ends_with(s.as_str()),
            Matcher::Regex(r) => r.is_match(value),
            Matcher::Number(cmp, rhs) => parse_number(value).is_some_and(|lhs| match cmp {
                Cmp::Gt => lhs > *rhs,
                Cmp::Ge => lhs >= *rhs,
                Cmp::Lt => lhs < *rhs,
                Cmp::Le => lhs <= *rhs,
            }),
        }
    }
}

impl Filter {
    /// Compiles one expression.
    pub fn parse(expr: &str) -> Result<Self, FilterError> {
        let err = |reason: &str| FilterError {
            expr: expr.to_string(),
            reason: reason.to_string(),
        };
        let op_at = expr
            .find(['=', '!', '<', '>'])
            .ok_or_else(|| err("missing operator (=, !=, >, >=, <, <=)"))?;
        let (lhs, rest) = expr.split_at(op_at);
        let (op, value) = ["!=", ">=", "<=", "=", ">", "<"]
            .iter()
            .find_map(|op| rest.strip_prefix(op).map(|v| (*op, v)))
            .ok_or_else(|| err("unknown operator"))?;
        let mut parts = lhs.split('|');
        let field = parts.next().unwrap_or_default().trim().to_string();
        if field.is_empty() {
            return Err(err("missing field name"));
        }
        let mods: Vec<&str> = parts.map(str::trim).collect();
        let cased = mods.contains(&"cased");
        let mut kind = None;
        let mut list = false;
        let mut exists = false;
        for m in &mods {
            match *m {
                "cased" => {}
                "in" => list = true,
                "exists" => exists = true,
                "contains" | "startswith" | "endswith" | "re" => {
                    if kind.replace(*m).is_some() {
                        return Err(err("only one of contains/startswith/endswith/re allowed"));
                    }
                }
                other => return Err(err(&format!("unknown modifier `{other}`"))),
            }
        }
        if exists {
            if op != "=" || !mods.iter().all(|m| *m == "exists") {
                return Err(err("|exists takes only `=true` or `=false`"));
            }
            let flag = match value.trim().to_ascii_lowercase().as_str() {
                "true" | "yes" | "1" => true,
                "false" | "no" | "0" => false,
                _ => return Err(err("|exists expects true or false")),
            };
            return Ok(Filter {
                field,
                negate: false,
                cased,
                exists: Some(flag),
                alternatives: Vec::new(),
            });
        }
        let cmp = match op {
            ">" => Some(Cmp::Gt),
            ">=" => Some(Cmp::Ge),
            "<" => Some(Cmp::Lt),
            "<=" => Some(Cmp::Le),
            _ => None,
        };
        let values: Vec<&str> = if list {
            value.split(',').map(str::trim).collect()
        } else {
            vec![value]
        };
        let mut alternatives = Vec::with_capacity(values.len());
        for v in values {
            alternatives.push(match (cmp, kind) {
                (Some(c), None) => Matcher::Number(
                    c,
                    parse_number(v).ok_or_else(|| err("ordering operators need a number"))?,
                ),
                (Some(_), Some(_)) => return Err(err("ordering operators take no match modifier")),
                (None, Some("contains")) => Matcher::Contains(fold(v, cased)),
                (None, Some("startswith")) => Matcher::StartsWith(fold(v, cased)),
                (None, Some("endswith")) => Matcher::EndsWith(fold(v, cased)),
                (None, Some(_)) => Matcher::Regex(
                    RegexBuilder::new(v)
                        .case_insensitive(!cased)
                        .size_limit(1 << 20)
                        .build()
                        .map_err(|e| err(&format!("bad regex: {e}")))?,
                ),
                (None, None) => Matcher::Glob(parse_glob(&fold(v, cased))),
            });
        }
        Ok(Filter {
            field,
            negate: op == "!=",
            cased,
            exists: None,
            alternatives,
        })
    }

    /// The field this filter tests.
    pub fn field(&self) -> &str {
        &self.field
    }

    /// Evaluates the filter against a record's fields.
    pub fn matches(&self, fields: &FieldMap) -> bool {
        if let Some(want) = self.exists {
            return fields.get_all(&self.field).next().is_some() == want;
        }
        let hit = fields
            .get_all(&self.field)
            .any(|v| self.alternatives.iter().any(|m| m.matches(v, self.cased)));
        hit != self.negate
    }
}

/// A conjunction of filters plus an optional free-text search.
#[derive(Debug, Clone, Default)]
pub struct FilterSet {
    filters: Vec<Filter>,
    text: Option<String>,
}

impl FilterSet {
    /// Compiles every expression.
    pub fn parse<S: AsRef<str>>(exprs: &[S]) -> Result<Self, FilterError> {
        Ok(FilterSet {
            filters: exprs
                .iter()
                .map(|e| Filter::parse(e.as_ref()))
                .collect::<Result<_, _>>()?,
            text: None,
        })
    }

    /// Adds a case-insensitive substring that must occur in some field value.
    pub fn with_text(mut self, text: Option<&str>) -> Self {
        self.text = text.filter(|t| !t.is_empty()).map(str::to_lowercase);
        self
    }

    /// True when there is nothing to test.
    pub fn is_empty(&self) -> bool {
        self.filters.is_empty() && self.text.is_none()
    }

    /// True if every filter matches (and the text, if any, occurs).
    pub fn matches(&self, fields: &FieldMap) -> bool {
        if let Some(t) = &self.text
            && !fields
                .iter()
                .any(|(_, v)| v.to_lowercase().contains(t.as_str()))
        {
            return false;
        }
        self.filters.iter().all(|f| f.matches(fields))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields() -> FieldMap {
        let mut f = FieldMap::new();
        f.insert("EventID", "4624");
        f.insert("Image", "C:\\Windows\\System32\\PING.EXE");
        f.insert("CommandLine", "ping  -n 6 127.0.0.1 ");
        f.insert("LogonType", "0x3");
        f.insert("Data_1", "alpha");
        f.insert("Data_1", "beta");
        f
    }

    fn m(expr: &str) -> bool {
        Filter::parse(expr).unwrap().matches(&fields())
    }

    #[test]
    fn equality_and_wildcards() {
        assert!(m("EventID=4624"));
        assert!(m("eventid=4624"));
        assert!(!m("EventID=4625"));
        assert!(m("EventID!=4625"));
        assert!(m("Image=*\\ping.exe"));
        assert!(!m("Image|cased=*\\ping.exe"));
        assert!(m("Image=c:\\windows\\system32\\p?ng.exe"));
        assert!(m("CommandLine=ping*127.*"));
        assert!(!m("CommandLine=ping"));
        assert!(m("Missing!=x"));
        assert!(!m("Missing=x"));
        assert!(m("Data_1=beta"), "any value of a repeated field");
        let mut lit = FieldMap::new();
        lit.insert("X", "a*b");
        assert!(Filter::parse("X=a\\*b").unwrap().matches(&lit));
        lit.insert("Y", "a-b");
        assert!(!Filter::parse("Y=a\\*b").unwrap().matches(&lit));
    }

    #[test]
    fn modifiers() {
        assert!(m("Image|endswith=\\ping.exe"));
        assert!(m("Image|startswith=c:\\windows"));
        assert!(m("CommandLine|contains=-n 6"));
        assert!(m("CommandLine|re=^ping\\s+-n\\s+\\d"));
        assert!(!m("CommandLine|re|cased=^PING"));
        assert!(m("EventID|in=4625, 4624"));
        assert!(m("Image|contains|in=notepad,ping"));
        assert!(m("Image|exists=true"));
        assert!(m("Nope|exists=false"));
        assert!(!m("Image|exists=no"));
    }

    #[test]
    fn numeric_comparisons() {
        assert!(m("EventID>4000"));
        assert!(m("EventID>=4624"));
        assert!(!m("EventID<4624"));
        assert!(m("EventID<=4624"));
        assert!(m("LogonType>=3"), "hex field values are numbers");
        assert!(m("LogonType<0x4"));
        assert!(!m("Image>1"), "non-numeric values never compare");
        assert_eq!(parse_number(" 0X1f "), Some(31.0));
        assert_eq!(parse_number("inf"), None);
    }

    #[test]
    fn parse_errors() {
        for bad in [
            "NoOperator",
            "=x",
            "F|bogus=x",
            "F|contains|endswith=x",
            "F>abc",
            "F|contains>1",
            "F|exists=maybe",
            "F|exists!=true",
            "F|re=(",
            "F!x",
        ] {
            let e = Filter::parse(bad).unwrap_err();
            assert_eq!(e.expr, bad);
            assert!(!e.to_string().is_empty());
        }
    }

    #[test]
    fn filter_sets() {
        let set = FilterSet::parse(&["EventID=4624", "Image|endswith=.exe"]).unwrap();
        assert!(set.matches(&fields()));
        assert!(!set.is_empty());
        assert!(set.clone().with_text(Some("127.0.0")).matches(&fields()));
        assert!(!set.with_text(Some("mimikatz")).matches(&fields()));
        let empty = FilterSet::parse::<&str>(&[]).unwrap().with_text(Some(""));
        assert!(empty.is_empty() && empty.matches(&fields()));
        assert_eq!(Filter::parse("A=1").unwrap().field(), "A");
    }

    #[test]
    fn glob_edge_cases() {
        let t = |p: &str, s: &str| glob_match(&parse_glob(p), &s.chars().collect::<Vec<_>>());
        assert!(t("*", ""));
        assert!(t("a*b*c", "aXbYbZc"));
        assert!(!t("a*b*c", "aXbY"));
        assert!(t("**a", "a"));
        assert!(!t("?", ""));
        assert!(t("\\", "\\"));
        assert!(t("a\\\\b", "a\\b"), "escaped backslash");
        assert!(t("C:\\Windows\\x*", "C:\\Windows\\xyz"), "plain backslashes are literal");
        assert!(t("C:\\dir\\\\*", "C:\\dir\\abc"), "`\\\\*` = backslash then wildcard");
        assert!(!t("a\\?", "ab"));
    }
}
