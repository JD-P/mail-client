//! Bounded, semantic HTML-email rendering for Ratatui.
//!
//! The rendering core performs no resource fetches or image decoding. It turns
//! untrusted HTML bytes into owned Ratatui lines; the Linux CLI invokes that
//! core through a disposable process boundary rather than parsing hostile HTML
//! in its interactive process.

pub mod app;
mod isolation;
mod parser;
mod render;
pub mod ui;

pub use isolation::{HtmlRenderIsolationConfig, IsolatedHtmlRenderer, IsolatedRenderError};
pub use parser::{HtmlDocument, Limits, ParseWarning, RenderError};
pub use render::{
    HtmlView, ImageReference, ImageSource, LinkKind, LinkReference, RenderOptions, RenderedPage,
    Theme,
};

#[doc(hidden)]
pub fn __run_html_render_worker() -> std::result::Result<(), String> {
    isolation::run_worker_process()
}

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
