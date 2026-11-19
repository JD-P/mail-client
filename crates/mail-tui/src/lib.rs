//! Bounded, semantic HTML-email rendering for Ratatui.
//!
//! This crate intentionally has no terminal driver, network client, filesystem
//! access, or image decoder.  It turns untrusted HTML bytes into owned Ratatui
//! lines which the caller may place in any widget or viewport.

mod parser;
mod render;

pub use parser::{HtmlDocument, Limits, ParseWarning, RenderError};
pub use render::{
    HtmlView, ImageReference, ImageSource, LinkKind, LinkReference, RenderOptions, RenderedPage,
    Theme,
};

/// Parses and renders untrusted HTML email with explicit resource limits.
#[derive(Debug, Clone, Default)]
pub struct HtmlRenderer {
    limits: Limits,
}

impl HtmlRenderer {
    pub fn new(limits: Limits) -> Self {
        Self { limits }
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    pub fn parse(&self, html: &[u8]) -> Result<HtmlDocument, RenderError> {
        HtmlDocument::parse(html, &self.limits)
    }

    pub fn render(
        &self,
        html: &[u8],
        width: u16,
        options: &RenderOptions,
    ) -> Result<RenderedPage, RenderError> {
        self.parse(html)?.render(width, options)
    }
}
