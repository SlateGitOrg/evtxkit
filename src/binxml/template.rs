//! Template definitions and their instantiation.
//!
//! Instantiation deep-copies the definition tree while replacing every
//! [`Substitution`](crate::model::Substitution) with the instance value:
//!
//! * **optional + empty** values (null, empty string/binary/array) disappear,
//!   and an attribute whose value becomes empty is dropped;
//! * embedded BinXML values (type 0x21) splice their element trees in place;
//! * **array** values with more than one item repeat the *containing element*
//!   once per item (MS-EVEN6 §3.1.4.7.5), recursing when an element contains
//!   several arrays.
//!
//! A [`NodeBudget`] bounds the memory: array expansion is a cross product and
//! every copy is a deep clone, so a hostile record could otherwise request
//! exponentially many nodes. Every node is charged when it is created or
//! cloned, at its full deep size (see [`node_cost`]).

use crate::error::{EvtxError, Result};
use crate::model::{Attribute, Element, Node};
use crate::value::{Guid, Value};

/// Heap bytes (string and binary payloads, array items) that cost one extra
/// budget unit on top of the node itself.
pub const BYTES_PER_UNIT: usize = 64;

/// A parsed template definition (cached per chunk by its offset).
#[derive(Debug, Clone)]
pub struct TemplateDef {
    /// Chunk-relative offset of the definition header.
    pub offset: usize,
    /// Template identifier GUID from the definition header.
    pub guid: Guid,
    /// Size in bytes of the definition's BinXML fragment.
    pub data_size: usize,
    /// Root element with unresolved substitutions.
    pub root: Element,
    /// How many times each substitution index occurs in `root`; lets
    /// instantiation move a value on its last use instead of cloning it.
    pub uses: Vec<u32>,
}

impl TemplateDef {
    /// Builds a definition and pre-computes substitution use counts.
    pub fn new(offset: usize, guid: Guid, data_size: usize, root: Element) -> Self {
        let mut uses = Vec::new();
        count_uses(&root, &mut uses);
        TemplateDef {
            offset,
            guid,
            data_size,
            root,
            uses,
        }
    }
}

fn count_uses(el: &Element, uses: &mut Vec<u32>) {
    let nodes = el
        .attributes
        .iter()
        .flat_map(|a| a.value.iter())
        .chain(el.children.iter());
    for n in nodes {
        match n {
            Node::Substitution(sub) => {
                let i = usize::from(sub.index);
                if uses.len() <= i {
                    uses.resize(i + 1, 0);
                }
                uses[i] += 1;
            }
            Node::Element(child) => count_uses(child, uses),
            _ => {}
        }
    }
}

/// One entry of a template instance's value array.
#[derive(Debug, Clone)]
pub enum TemplateValue {
    /// A scalar or array value.
    Value(Value),
    /// An embedded BinXML fragment, already parsed into nodes.
    Xml(Vec<Node>),
}

/// A decoded-node allowance. One budget is shared by every template instance
/// of a record, so nested or repeated instances cannot each start afresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeBudget {
    remaining: usize,
    limit: usize,
    scope: &'static str,
}

impl NodeBudget {
    /// A budget of `remaining` units; exhausting it reports `limit` and
    /// `scope` in [`EvtxError::ExpansionLimit`].
    pub fn new(remaining: usize, limit: usize, scope: &'static str) -> Self {
        NodeBudget {
            remaining,
            limit,
            scope,
        }
    }

    /// Units still available.
    pub fn remaining(&self) -> usize {
        self.remaining
    }

    /// Takes `n` units, or fails without taking any.
    pub fn spend(&mut self, n: usize) -> Result<()> {
        if n > self.remaining {
            return Err(EvtxError::ExpansionLimit {
                limit: self.limit,
                scope: self.scope,
            });
        }
        self.remaining -= n;
        Ok(())
    }
}

/// Instantiates `template` with `values`, charging every created node to
/// `budget`.
///
/// Values are moved into the tree on their last use and cloned before that,
/// so `values` is left partially consumed.
pub fn instantiate(
    template: &TemplateDef,
    values: &mut [TemplateValue],
    budget: &mut NodeBudget,
) -> Result<Vec<Element>> {
    let mut inst = Instantiator {
        values,
        uses: template.uses.clone(),
        budget,
    };
    inst.element(&template.root)
}

struct Instantiator<'v> {
    values: &'v mut [TemplateValue],
    uses: Vec<u32>,
    budget: &'v mut NodeBudget,
}

/// Where the first expandable array sat inside an element.
enum ArrayLoc {
    Child(usize),
    Attr(usize, usize),
}

impl ArrayLoc {
    /// The node list holding the array and the array's index in it.
    fn slot<'e>(&self, el: &'e mut Element) -> (&'e mut Vec<Node>, usize) {
        match *self {
            ArrayLoc::Child(i) => (&mut el.children, i),
            ArrayLoc::Attr(a, i) => (&mut el.attributes[a].value, i),
        }
    }
}

/// Heap bytes owned by a value (payloads and array items).
fn heap_bytes(v: &Value) -> usize {
    match v {
        Value::String(s) | Value::AnsiString(s) => s.len(),
        Value::Binary(b) => b.len(),
        Value::Sid(sid) => sid.0.len(),
        Value::Array(items) => items
            .iter()
            .map(|i| std::mem::size_of::<Value>() + heap_bytes(i))
            .sum(),
        _ => 0,
    }
}

/// Budget units for one value node: 1 plus one per [`BYTES_PER_UNIT`] heap bytes.
pub fn value_cost(v: &Value) -> usize {
    1 + heap_bytes(v) / BYTES_PER_UNIT
}

/// Budget units for a node *including its whole subtree*: what creating or
/// deep-cloning it costs.
pub fn node_cost(n: &Node) -> usize {
    match n {
        Node::Element(e) => element_cost(e),
        Node::Value(v) => value_cost(v),
        Node::CData(s) | Node::ProcessingInstruction { data: s, .. } => {
            1 + s.len() / BYTES_PER_UNIT
        }
        Node::CharRef(_) | Node::EntityRef(_) | Node::Substitution(_) => 1,
    }
}

/// Budget units for an element, its attributes and all descendants.
pub fn element_cost(e: &Element) -> usize {
    let attrs: usize = e.attributes.iter().map(|a| 1 + nodes_cost(&a.value)).sum();
    1 + attrs + nodes_cost(&e.children)
}

fn nodes_cost(nodes: &[Node]) -> usize {
    nodes.iter().map(node_cost).sum()
}

impl Instantiator<'_> {
    fn element(&mut self, el: &Element) -> Result<Vec<Element>> {
        self.budget.spend(1)?;
        let mut out = Element {
            name: el.name.clone(),
            attributes: Vec::with_capacity(el.attributes.len()),
            children: Vec::with_capacity(el.children.len()),
        };
        for attr in &el.attributes {
            let mut value = Vec::with_capacity(attr.value.len());
            for node in &attr.value {
                self.resolve_into(node, &mut value)?;
            }
            if !value.is_empty() {
                self.budget.spend(1)?;
                out.attributes.push(Attribute {
                    name: attr.name.clone(),
                    value,
                });
            }
        }
        for node in &el.children {
            self.resolve_into(node, &mut out.children)?;
        }
        self.expand_arrays(out)
    }

    fn resolve_into(&mut self, node: &Node, out: &mut Vec<Node>) -> Result<()> {
        match node {
            Node::Substitution(sub) => {
                let i = usize::from(sub.index);
                // Out-of-range indexes resolve to nothing (fail-soft, as Windows does).
                let Some(value) = self.values.get_mut(i) else {
                    return Ok(());
                };
                let cost = match &*value {
                    TemplateValue::Value(v) if sub.optional && v.is_empty() => return Ok(()),
                    TemplateValue::Value(v) => value_cost(v),
                    TemplateValue::Xml(nodes) => nodes_cost(nodes),
                };
                self.budget.spend(cost)?;
                let last_use = self.uses.get(i).is_none_or(|&u| u <= 1);
                if let Some(u) = self.uses.get_mut(i) {
                    *u = u.saturating_sub(1);
                }
                let taken = if last_use {
                    std::mem::replace(value, TemplateValue::Value(Value::Null))
                } else {
                    value.clone()
                };
                match taken {
                    TemplateValue::Value(v) => out.push(Node::Value(v)),
                    TemplateValue::Xml(nodes) => out.extend(nodes),
                }
            }
            Node::Element(e) => {
                for resolved in self.element(e)? {
                    out.push(Node::Element(resolved));
                }
            }
            other => {
                self.budget.spend(node_cost(other))?;
                out.push(other.clone());
            }
        }
        Ok(())
    }

    /// Removes the first array with more than one item (children before
    /// attributes) and returns where it was, leaving a `Null` placeholder.
    fn take_array(el: &mut Element) -> Option<(ArrayLoc, Vec<Value>)> {
        let expandable =
            |n: &Node| matches!(n, Node::Value(Value::Array(items)) if items.len() > 1);
        let loc = match el.children.iter().position(expandable) {
            Some(i) => ArrayLoc::Child(i),
            None => el.attributes.iter().enumerate().find_map(|(a, attr)| {
                attr.value
                    .iter()
                    .position(expandable)
                    .map(|i| ArrayLoc::Attr(a, i))
            })?,
        };
        let (nodes, i) = loc.slot(el);
        match std::mem::replace(&mut nodes[i], Node::Value(Value::Null)) {
            Node::Value(Value::Array(items)) => Some((loc, items)),
            other => {
                nodes[i] = other;
                None
            }
        }
    }

    /// Repeats `el` once per item of its first multi-item array, recursing for
    /// further arrays. Each copy is charged its full deep size before cloning.
    fn expand_arrays(&mut self, mut el: Element) -> Result<Vec<Element>> {
        let Some((loc, items)) = Self::take_array(&mut el) else {
            return Ok(vec![el]);
        };
        // The placeholder is charged as one node; the item replaces it.
        let base = element_cost(&el);
        let mut out = Vec::new();
        for item in items {
            self.budget.spend(base + value_cost(&item))?;
            let mut copy = el.clone();
            let (nodes, i) = loc.slot(&mut copy);
            if item.is_empty() {
                nodes.remove(i);
            } else {
                nodes[i] = Node::Value(item);
            }
            out.extend(self.expand_arrays(copy)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Substitution;

    fn sub(index: u16, optional: bool) -> Node {
        Node::Substitution(Substitution {
            index,
            value_type: 1,
            optional,
        })
    }

    fn s(v: &str) -> Value {
        Value::String(v.into())
    }

    fn def(root: Element) -> TemplateDef {
        TemplateDef::new(0, Guid([0; 16]), 0, root)
    }

    fn budget(n: usize) -> NodeBudget {
        NodeBudget::new(n, n, "record")
    }

    fn template() -> Element {
        let mut root = Element::new("Event");
        let mut a = Element::new("A");
        a.attributes.push(Attribute {
            name: "opt".into(),
            value: vec![sub(0, true)],
        });
        a.attributes.push(Attribute {
            name: "req".into(),
            value: vec![sub(0, false)],
        });
        a.children.push(sub(1, false));
        root.children.push(Node::Element(a));
        let mut data = Element::new("Data");
        data.children.push(sub(2, false));
        root.children.push(Node::Element(data));
        root.children.push(sub(3, true));
        root.children.push(sub(9, false));
        root
    }

    #[test]
    fn optional_empty_values_vanish_and_arrays_repeat() {
        let values = vec![
            TemplateValue::Value(Value::Null),
            TemplateValue::Value(s("x")),
            TemplateValue::Value(Value::Array(vec![s("a"), s(""), s("c")])),
            TemplateValue::Xml(vec![Node::Element(Element::new("Nested"))]),
        ];
        let def = TemplateDef::new(0, Guid([0; 16]), 0, template());
        assert_eq!(def.uses, vec![2, 1, 1, 1, 0, 0, 0, 0, 0, 1]);
        let out = instantiate(&def, &mut values.clone(), &mut budget(1000)).unwrap();
        assert_eq!(out.len(), 1);
        let root = &out[0];
        let a = root.child("A").unwrap();
        assert_eq!(a.attr("opt"), None, "optional null attribute dropped");
        assert_eq!(a.attr("req").as_deref(), Some(""), "required null kept");
        assert_eq!(a.text(), "x");
        let datas: Vec<String> = root
            .child_elements()
            .filter(|e| &*e.name == "Data")
            .map(Element::text)
            .collect();
        assert_eq!(datas, vec!["a", "", "c"]);
        assert!(root.child("Nested").is_some());
    }

    #[test]
    fn single_item_arrays_do_not_repeat_and_attr_arrays_expand() {
        let mut root = Element::new("R");
        root.attributes.push(Attribute {
            name: "k".into(),
            value: vec![sub(0, false)],
        });
        root.children.push(sub(1, false));
        let values = vec![
            TemplateValue::Value(Value::Array(vec![Value::UInt8(1), Value::UInt8(2)])),
            TemplateValue::Value(Value::Array(vec![s("only")])),
        ];
        let out = instantiate(&def(root), &mut values.clone(), &mut budget(1000)).unwrap();
        let ks: Vec<_> = out.iter().map(|e| e.attr("k").unwrap()).collect();
        assert_eq!(ks, vec!["1", "2"]);
        assert!(out.iter().all(|e| e.text() == "only"));
    }

    #[test]
    fn cross_product_is_bounded() {
        let mut root = Element::new("R");
        for i in 0..20 {
            root.children.push(sub(i, false));
        }
        let arr = TemplateValue::Value(Value::Array(vec![s("a"), s("b")]));
        let values = vec![arr; 20];
        let err = instantiate(&def(root), &mut values.clone(), &mut budget(10_000)).unwrap_err();
        assert_eq!(
            err,
            EvtxError::ExpansionLimit {
                limit: 10_000,
                scope: "record"
            }
        );
    }

    #[test]
    fn optional_empty_xml_vanishes() {
        let mut root = Element::new("R");
        root.children.push(sub(0, true));
        let out = instantiate(
            &def(root),
            &mut [TemplateValue::Xml(vec![])],
            &mut budget(10),
        )
        .unwrap();
        assert!(out[0].children.is_empty());
        assert_eq!(node_cost(&Node::CharRef(1)), 1);
    }

    /// `<E>%0<F>%1 x uses</F></E>`, `%0` an array of `items` UInt8s and `%1`
    /// a BinXML value of `xml` empty elements (a crafted-file shape that amplifies memory use).
    fn clone_bomb(items: usize, uses: u16, xml: usize) -> (TemplateDef, Vec<TemplateValue>) {
        let mut f = Element::new("F");
        for _ in 0..uses {
            f.children.push(sub(1, false));
        }
        let mut e = Element::new("E");
        e.children.push(sub(0, false));
        e.children.push(Node::Element(f));
        let values = vec![
            TemplateValue::Value(Value::Array(
                (0..items).map(|i| Value::UInt8(i as u8)).collect(),
            )),
            TemplateValue::Xml((0..xml).map(|_| Node::Element(Element::new("G"))).collect()),
        ];
        (def(e), values)
    }

    #[test]
    fn array_copies_are_charged_their_full_deep_size() {
        // Before the fix each copy cost 3 units while cloning ~50,000 nodes:
        // 10 items produced 500,000 elements under a 100,000 budget.
        let (d, mut values) = clone_bomb(10, 50, 1000);
        let err = instantiate(&d, &mut values, &mut budget(100_000)).unwrap_err();
        assert!(matches!(
            err,
            EvtxError::ExpansionLimit { limit: 100_000, .. }
        ));
    }

    #[test]
    fn spent_units_cover_everything_returned() {
        // Invariant behind threat-model item T4: whatever instantiation
        // returns was paid for, so `limit` bounds the tree it can build.
        for items in [0, 1, 2, 3, 7] {
            for uses in [0, 1, 2, 5] {
                for xml in [0, 1, 4, 30] {
                    let (d, mut values) = clone_bomb(items, uses, xml);
                    let mut b = budget(1_000_000);
                    let out = instantiate(&d, &mut values, &mut b).unwrap();
                    let built: usize = out.iter().map(element_cost).sum();
                    let spent = 1_000_000 - b.remaining();
                    assert!(
                        built <= spent,
                        "items={items} uses={uses} xml={xml}: built {built} > spent {spent}"
                    );
                }
            }
        }
    }

    #[test]
    fn large_payloads_cost_by_size() {
        // A long string cloned into every array copy: few nodes, many bytes.
        let mut e = Element::new("E");
        e.children.push(sub(0, false));
        e.children.push(sub(1, false));
        let long = TemplateValue::Value(s(&"A".repeat(16_000)));
        let items = (0..25_000).map(|i| Value::UInt8(i as u8)).collect();
        let mut values = vec![long, TemplateValue::Value(Value::Array(items))];
        let err = instantiate(&def(e), &mut values, &mut budget(100_000)).unwrap_err();
        assert!(matches!(err, EvtxError::ExpansionLimit { .. }));
        assert_eq!(value_cost(&s(&"A".repeat(640))), 11);
        assert_eq!(
            value_cost(&Value::Binary(vec![0; 64]))
                + value_cost(&Value::Sid(crate::value::Sid(vec![0; 8]))),
            3
        );
        let cdata = Node::CData("x".repeat(128));
        assert_eq!(node_cost(&cdata), 3);
    }

    #[test]
    fn budget_failure_takes_nothing() {
        let mut b = budget(5);
        assert!(b.spend(6).is_err());
        assert_eq!(b.remaining(), 5);
        b.spend(5).unwrap();
        assert_eq!(b.remaining(), 0);
    }
}
