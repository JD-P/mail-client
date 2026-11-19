# Lizard mail TUI

This crate now contains both the bounded HTML-email renderer and the first
working terminal client for the opinionated Warm/Cold/Spam workflow specified
in [`../../spec/tui-workflows.md`](../../spec/tui-workflows.md).
The exact implementation boundary is tracked in
[`../../spec/tui-implementation-status.md`](../../spec/tui-implementation-status.md).

Run the client against a Lizard backend profile:

```sh
cargo run -p lizard-mail-tui -- /path/to/profile
```

The implemented client opens directly into Warm — Action, or into bounded
contact onboarding when the first configured account has mail but no contacts.
Global keys switch between Warm Action, Warm FYI, Cold Review, Spam, Waiting,
Snoozed, Done, Contacts, and contextual Help. Done/Waiting/Snooze and Make
Actionable Once are durable backend operations. Serious open-interstitial
findings block the ordinary reader until the user explicitly chooses restricted
viewing.

## HTML renderer

This crate renders the project's bounded HTML-email subset as semantic Ratatui
text. It is deliberately separate from the graphical Lizard renderer: terminal
cells are not pixels, and pretending otherwise makes inaccessible, unstable
mail.

The renderer has no network or filesystem capability. Remote and embedded
images become labelled placeholders; links become inert numbered references;
forms and active content are omitted. Author colors and layout CSS are ignored
so that hostile mail cannot make text invisible against the terminal theme.

## Terminal mapping

- headings, emphasis, deletion, code, quotations, preformatted text,
  descriptions, and nested ordered/unordered lists retain their semantics;
- tables use a bounded cell grid when it fits, and labelled stacked records on
  narrow terminals;
- `colspan` and `rowspan` affect reading order without duplicating content;
- links receive stable footnote numbers and canonical destinations; unsafe
  schemes are labelled but never repeated as actionable text;
- images produce `[Image: alt text]` or `[Image omitted]` and a metadata record;
- forms produce one `[Interactive form omitted]` notice; active content and
  external stylesheets are discarded;
- inline visibility, whitespace, alignment, emphasis, decoration, and text
  transform declarations are honored. Colors, backgrounds, geometry, and
  remote CSS are intentionally not terminal presentation concepts.

The parser, copied DOM, attributes, nesting, table cells, links, images, output
lines, and output cells all have caller-configurable limits. C0/C1 terminal
controls are neutralized, as are Unicode bidi embedding/override controls that
could otherwise reorder a displayed address or link.

```rust
use lizard_mail_tui::{HtmlRenderer, RenderOptions};

let page = HtmlRenderer::default().render(
    br#"<h1>Hello</h1><p>See <a href='https://example.com'>the site</a>.</p>"#,
    80,
    &RenderOptions::default(),
)?;

// Use `page.lines` in a Ratatui Paragraph, or `page.widget()` directly.
# Ok::<(), lizard_mail_tui::RenderError>(())
```
