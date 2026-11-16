#![forbid(unsafe_code)]
//! html5ever is an explicit unverified parsing adapter. Core nodes use arena IDs.
use crate::core::*;
use html5ever::{parse_document, tendril::TendrilSink};
use markup5ever_rcdom::{NodeData, RcDom};
use serde::Serialize;
pub type NodeId = usize;
#[derive(Clone, Debug, Serialize)]
pub enum Kind {
    Document,
    Element,
    Text,
    Comment,
}
#[derive(Clone, Debug, Serialize)]
pub struct Node {
    pub kind: Kind,
    pub tag: String,
    pub text: String,
    pub attrs: Vec<(String, String)>,
    pub parent: Option<NodeId>,
    pub children: Vec<NodeId>,
    pub depth: usize,
    pub disabled: bool,
}
impl Node {
    pub fn attr(&self, n: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == n)
            .map(|(_, v)| v.as_str())
    }
    pub fn element(&self) -> bool {
        matches!(self.kind, Kind::Element)
    }
}
#[derive(Clone, Debug, Serialize)]
pub struct Document {
    pub nodes: Vec<Node>,
    pub stylesheets: Vec<String>,
    pub source_bytes: usize,
}
impl Document {
    pub fn parse(bytes: &[u8], limits: &Limits, budget: &mut Budget) -> Result<Self> {
        if bytes.len() > limits.html_bytes {
            return Err(Error::Budget("HTML bytes"));
        }
        budget.charge(bytes.len() as u64)?;
        // Conservative allocation preflight, followed by exact arena/depth checks.
        // html5ever's own allocations remain an unverified dependency boundary.
        if bytes.iter().filter(|b| **b == b'<').count() > limits.nodes / 4 {
            return Err(Error::Budget("HTML tokens"));
        }
        let input = String::from_utf8_lossy(bytes);
        let parsed = parse_document(RcDom::default(), Default::default()).one(input.as_ref());
        let mut doc = Self {
            nodes: vec![],
            stylesheets: vec![],
            source_bytes: bytes.len(),
        };
        let mut stack = vec![(parsed.document.clone(), None, 0usize, false)];
        while let Some((handle, parent, depth, inactive)) = stack.pop() {
            budget.charge(1)?;
            if doc.nodes.len() >= limits.nodes {
                return Err(Error::Budget("DOM nodes"));
            }
            if depth > limits.depth {
                return Err(Error::Budget("DOM depth"));
            }
            let (kind, tag, text, attrs) = match &handle.data {
                NodeData::Document => (Kind::Document, String::new(), String::new(), vec![]),
                NodeData::Element { name, attrs, .. } => (
                    Kind::Element,
                    name.local.to_string(),
                    String::new(),
                    attrs
                        .borrow()
                        .iter()
                        .map(|a| (a.name.local.to_string(), a.value.to_string()))
                        .collect(),
                ),
                NodeData::Text { contents } => (
                    Kind::Text,
                    String::new(),
                    contents.borrow().to_string(),
                    vec![],
                ),
                NodeData::Comment { contents } => {
                    (Kind::Comment, String::new(), contents.to_string(), vec![])
                }
                _ => continue,
            };
            let disabled = inactive
                || matches!(
                    tag.as_str(),
                    "script"
                        | "iframe"
                        | "object"
                        | "embed"
                        | "svg"
                        | "math"
                        | "template"
                        | "noscript"
                );
            let id = doc.nodes.len();
            doc.nodes.push(Node {
                kind,
                tag,
                text,
                attrs,
                parent,
                children: vec![],
                depth,
                disabled,
            });
            if let Some(p) = parent {
                doc.nodes[p].children.push(id);
            }
            for c in handle.children.borrow().iter().rev() {
                stack.push((c.clone(), Some(id), depth + 1, disabled));
            }
        }
        for n in &doc.nodes {
            if n.tag == "style" && !n.disabled {
                let mut s = String::new();
                for c in &n.children {
                    if matches!(doc.nodes[*c].kind, Kind::Text) {
                        s.push_str(&doc.nodes[*c].text);
                    }
                }
                if s.len() > limits.css_bytes {
                    return Err(Error::Budget("stylesheet bytes"));
                }
                doc.stylesheets.push(s);
            }
        }
        Ok(doc)
    }
    pub fn previous_element(&self, id: NodeId) -> Option<NodeId> {
        let p = self.nodes[id].parent?;
        let siblings = &self.nodes[p].children;
        let pos = siblings.iter().position(|x| *x == id)?;
        siblings[..pos]
            .iter()
            .rev()
            .find(|i| self.nodes[**i].element())
            .copied()
    }
    pub fn text_content(&self, id: NodeId) -> String {
        let mut out = String::new();
        let mut stack = vec![id];
        while let Some(i) = stack.pop() {
            let n = &self.nodes[i];
            if n.disabled {
                continue;
            }
            if matches!(n.kind, Kind::Text) {
                out.push_str(&n.text);
            } else {
                for c in n.children.iter().rev() {
                    stack.push(*c);
                }
            }
        }
        out
    }
    pub fn readable_text(&self) -> String {
        let mut out = String::new();
        for n in &self.nodes {
            if n.disabled || matches!(n.tag.as_str(), "style" | "head" | "title") {
                continue;
            }
            let mut p = n.parent;
            let mut hidden = false;
            while let Some(i) = p {
                if matches!(self.nodes[i].tag.as_str(), "head" | "style" | "title") {
                    hidden = true;
                    break;
                }
                p = self.nodes[i].parent;
            }
            if !hidden && matches!(n.kind, Kind::Text) {
                out.push_str(&n.text);
                out.push(' ');
            }
        }
        out
    }
}
