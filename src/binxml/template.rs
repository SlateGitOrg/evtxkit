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
//! A node budget bounds the work: array expansion is a cross product, so a
//! hostile record could otherwise request exponentially many nodes.

use crate::error::{EvtxError, Result};
use crate::model::{Attribute, Element, Node};
use crate::value::{Guid, Value};

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

/// Instantiates `template` with `values`, spending at most `budget` nodes.
///
/// Values are moved into the tree on their last use and cloned before that,
/// so `values` is left partially consumed.
pub fn instantiate(
    template: &TemplateDef,
    values: &mut [TemplateValue],
    budget: usize,
) -> Result<Vec<Element>> {
    let mut inst = Instantiator {
        values,
        uses: template.uses.clone(),
        remaining: budget,
        limit: budget,
    };
    inst.element(&template.root)
}

struct Instantiator<'v> {
    values: &'v mut [TemplateValue],
    uses: Vec<u32>,
    remaining: usize,
    limit: usize,
}

/// Where the first expandable array sits inside an element.
enum ArrayLoc {
    Child(usize),
    Attr(usize, usize),
}

fn count_nodes(nodes: &[Node]) -> usize {
    nodes
        .iter()
        .map(|n| match n {
            Node::Element(e) => 1 + e.attributes.len() + count_nodes(&e.children),
            _ => 1,
        })
        .sum()
}

impl Instantiator<'_> {
    fn spend(&mut self, n: usize) -> Result<()> {
        if n > self.remaining {
            return Err(EvtxError::ExpansionLimit { limit: self.limit });
        }
        self.remaining -= n;
        Ok(())
    }

    fn element(&mut self, el: &Element) -> Result<Vec<Element>> {
        self.spend(1)?;
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
                    TemplateValue::Value(_) => 1,
                    TemplateValue::Xml(nodes) => count_nodes(nodes),
                };
                if cost > self.remaining {
                    return Err(EvtxError::ExpansionLimit { limit: self.limit });
                }
                self.remaining -= cost;
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
                self.spend(1)?;
                out.push(other.clone());
            }
        }
        Ok(())
    }

    fn find_array(el: &Element) -> Option<(ArrayLoc, Vec<Value>)> {
        let expandable = |n: &Node| match n {
            Node::Value(Value::Array(items)) if items.len() > 1 => Some(items.clone()),
            _ => None,
        };
        for (i, n) in el.children.iter().enumerate() {
            if let Some(items) = expandable(n) {
                return Some((ArrayLoc::Child(i), items));
            }
        }
        for (a, attr) in el.attributes.iter().enumerate() {
            for (i, n) in attr.value.iter().enumerate() {
                if let Some(items) = expandable(n) {
                    return Some((ArrayLoc::Attr(a, i), items));
                }
            }
        }
        None
    }

    fn expand_arrays(&mut self, el: Element) -> Result<Vec<Element>> {
        let Some((loc, items)) = Self::find_array(&el) else {
            return Ok(vec![el]);
        };
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            self.spend(1 + el.children.len() + el.attributes.len())?;
            let mut copy = el.clone();
            let slot = match loc {
                ArrayLoc::Child(i) => (&mut copy.children, i),
                ArrayLoc::Attr(a, i) => (&mut copy.attributes[a].value, i),
            };
            if item.is_empty() {
                slot.0.remove(slot.1);
            } else {
                slot.0[slot.1] = Node::Value(item);
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
        let out = instantiate(&def, &mut values.clone(), 1000).unwrap();
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
        let out = instantiate(&def(root), &mut values.clone(), 1000).unwrap();
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
        let err = instantiate(&def(root), &mut values.clone(), 10_000).unwrap_err();
        assert_eq!(err, EvtxError::ExpansionLimit { limit: 10_000 });
    }

    #[test]
    fn optional_empty_xml_vanishes() {
        let mut root = Element::new("R");
        root.children.push(sub(0, true));
        let out = instantiate(&def(root), &mut [TemplateValue::Xml(vec![])], 10).unwrap();
        assert!(out[0].children.is_empty());
        assert_eq!(count_nodes(&[Node::CharRef(1)]), 1);
    }
}
