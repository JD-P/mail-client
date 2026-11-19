use std::{collections::BTreeMap, fmt, io::Cursor};

use html5ever::{parse_document, tendril::TendrilSink};
use markup5ever_rcdom::{Handle, NodeData, RcDom};
use serde::{Deserialize, Serialize};

use crate::render::{RenderOptions, RenderedPage};

/// Hard limits applied before and after the HTML5 parser boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Limits {
    pub max_input_bytes: usize,
    pub max_markup_tokens: usize,
    pub max_nodes: usize,
    pub max_depth: usize,
    pub max_attributes_per_element: usize,
    pub max_attribute_bytes: usize,
    pub max_text_bytes: usize,
    pub max_links: usize,
    pub max_images: usize,
    pub max_table_cells: usize,
    pub max_output_lines: usize,
    pub max_output_cells: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_input_bytes: 4 * 1024 * 1024,
            max_markup_tokens: 200_000,
            max_nodes: 200_000,
            max_depth: 128,
            max_attributes_per_element: 128,
            max_attribute_bytes: 64 * 1024,
            max_text_bytes: 4 * 1024 * 1024,
            max_links: 4_096,
            max_images: 4_096,
            max_table_cells: 65_536,
            max_output_lines: 50_000,
            max_output_cells: 4 * 1024 * 1024,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseWarning {
    ActiveContentRemoved,
    StylesheetIgnored,
    UnsupportedElement(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    InputTooLarge { actual: usize, limit: usize },
    TooManyMarkupTokens { limit: usize },
    TooManyNodes { limit: usize },
    TreeTooDeep { limit: usize },
    TooManyAttributes { limit: usize },
    AttributesTooLarge { limit: usize },
    TextTooLarge { limit: usize },
    ParserIo(String),
    InvalidWidth,
}

impl fmt::Display for RenderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InputTooLarge { actual, limit } => {
                write!(f, "HTML input is {actual} bytes; limit is {limit}")
            }
            Self::TooManyMarkupTokens { limit } => {
                write!(f, "HTML contains more than {limit} markup tokens")
            }
            Self::TooManyNodes { limit } => write!(f, "HTML tree exceeds {limit} nodes"),
            Self::TreeTooDeep { limit } => write!(f, "HTML tree exceeds depth {limit}"),
            Self::TooManyAttributes { limit } => {
                write!(f, "an HTML element exceeds {limit} attributes")
            }
            Self::AttributesTooLarge { limit } => {
                write!(f, "HTML attributes exceed the {limit}-byte budget")
            }
            Self::TextTooLarge { limit } => {
                write!(f, "decoded HTML text exceeds the {limit}-byte budget")
            }
            Self::ParserIo(message) => write!(f, "HTML parser failed: {message}"),
            Self::InvalidWidth => write!(f, "terminal rendering width must be at least one cell"),
        }
    }
}

impl std::error::Error for RenderError {}

#[derive(Debug, Clone)]
pub(crate) enum Node {
    Text(String),
    Element(Element),
}

#[derive(Debug, Clone)]
pub(crate) struct Element {
    pub(crate) tag: String,
    pub(crate) attributes: BTreeMap<String, String>,
    pub(crate) children: Vec<Node>,
}

impl Element {
    pub(crate) fn attr(&self, name: &str) -> Option<&str> {
        self.attributes.get(name).map(String::as_str)
    }
}

#[derive(Debug, Clone)]
pub struct HtmlDocument {
    pub(crate) children: Vec<Node>,
    pub(crate) limits: Limits,
    warnings: Vec<ParseWarning>,
}

impl HtmlDocument {
    pub fn parse(input: &[u8], limits: &Limits) -> Result<Self, RenderError> {
        if input.len() > limits.max_input_bytes {
            return Err(RenderError::InputTooLarge {
                actual: input.len(),
                limit: limits.max_input_bytes,
            });
        }

        // html5ever does not expose an allocation budget.  This inexpensive
        // preflight caps the maximum amount of parser structure an input can
        // request before entering that dependency.
        let token_estimate = input
            .iter()
            .filter(|byte| matches!(byte, b'<' | b'&'))
            .take(limits.max_markup_tokens + 1)
            .count();
        if token_estimate > limits.max_markup_tokens {
            return Err(RenderError::TooManyMarkupTokens {
                limit: limits.max_markup_tokens,
            });
        }

        let dom = parse_document(RcDom::default(), Default::default())
            .from_utf8()
            .read_from(&mut Cursor::new(input))
            .map_err(|error| RenderError::ParserIo(error.to_string()))?;

        let mut budget = ParseBudget::new(limits);
        let children = convert_children(&dom.document, 0, &mut budget)?;
        Ok(Self {
            children,
            limits: limits.clone(),
            warnings: budget.warnings,
        })
    }

    pub fn warnings(&self) -> &[ParseWarning] {
        &self.warnings
    }

    pub fn render(&self, width: u16, options: &RenderOptions) -> Result<RenderedPage, RenderError> {
        crate::render::render_document(self, width, options)
    }
}

struct ParseBudget<'a> {
    limits: &'a Limits,
    nodes: usize,
    attribute_bytes: usize,
    text_bytes: usize,
    warnings: Vec<ParseWarning>,
}

impl<'a> ParseBudget<'a> {
    fn new(limits: &'a Limits) -> Self {
        Self {
            limits,
            nodes: 0,
            attribute_bytes: 0,
            text_bytes: 0,
            warnings: Vec::new(),
        }
    }

    fn count_node(&mut self) -> Result<(), RenderError> {
        self.nodes += 1;
        if self.nodes > self.limits.max_nodes {
            Err(RenderError::TooManyNodes {
                limit: self.limits.max_nodes,
            })
        } else {
            Ok(())
        }
    }

    fn warn(&mut self, warning: ParseWarning) {
        if !self.warnings.contains(&warning) {
            self.warnings.push(warning);
        }
    }
}

fn convert_children(
    handle: &Handle,
    depth: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<Vec<Node>, RenderError> {
    if depth > budget.limits.max_depth {
        return Err(RenderError::TreeTooDeep {
            limit: budget.limits.max_depth,
        });
    }

    let handles: Vec<Handle> = handle.children.borrow().iter().cloned().collect();
    let mut result = Vec::with_capacity(handles.len().min(256));
    for child in handles {
        if let Some(converted) = convert_node(&child, depth + 1, budget)? {
            result.push(converted);
        }
    }
    Ok(result)
}

fn convert_node(
    handle: &Handle,
    depth: usize,
    budget: &mut ParseBudget<'_>,
) -> Result<Option<Node>, RenderError> {
    budget.count_node()?;
    if depth > budget.limits.max_depth {
        return Err(RenderError::TreeTooDeep {
            limit: budget.limits.max_depth,
        });
    }

    match &handle.data {
        NodeData::Text { contents } => {
            let text = contents.borrow().to_string();
            budget.text_bytes = budget.text_bytes.saturating_add(text.len());
            if budget.text_bytes > budget.limits.max_text_bytes {
                return Err(RenderError::TextTooLarge {
                    limit: budget.limits.max_text_bytes,
                });
            }
            Ok((!text.is_empty()).then_some(Node::Text(text)))
        }
        NodeData::Element { name, attrs, .. } => {
            let tag = name.local.to_string().to_ascii_lowercase();
            if is_active_or_non_content(&tag) {
                budget.warn(ParseWarning::ActiveContentRemoved);
                return Ok(None);
            }
            if tag == "style" || tag == "link" {
                budget.warn(ParseWarning::StylesheetIgnored);
                return Ok(None);
            }

            let attrs = attrs.borrow();
            if attrs.len() > budget.limits.max_attributes_per_element {
                return Err(RenderError::TooManyAttributes {
                    limit: budget.limits.max_attributes_per_element,
                });
            }
            let mut attributes = BTreeMap::new();
            for attribute in attrs.iter() {
                let key = attribute.name.local.to_string().to_ascii_lowercase();
                let value = attribute.value.to_string();
                budget.attribute_bytes = budget
                    .attribute_bytes
                    .saturating_add(key.len())
                    .saturating_add(value.len());
                if budget.attribute_bytes > budget.limits.max_attribute_bytes {
                    return Err(RenderError::AttributesTooLarge {
                        limit: budget.limits.max_attribute_bytes,
                    });
                }
                attributes.insert(key, value);
            }
            drop(attrs);

            let children = convert_children(handle, depth, budget)?;
            Ok(Some(Node::Element(Element {
                tag,
                attributes,
                children,
            })))
        }
        NodeData::Document => Ok(Some(Node::Element(Element {
            tag: "#document".to_owned(),
            attributes: BTreeMap::new(),
            children: convert_children(handle, depth, budget)?,
        }))),
        _ => Ok(None),
    }
}

fn is_active_or_non_content(tag: &str) -> bool {
    matches!(
        tag,
        "script"
            | "iframe"
            | "frame"
            | "frameset"
            | "object"
            | "embed"
            | "applet"
            | "svg"
            | "math"
            | "template"
            | "noscript"
            | "audio"
            | "video"
            | "canvas"
            | "meta"
            | "base"
    )
}
