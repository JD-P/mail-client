# Lizard mail TUI

This crate now contains both the bounded HTML-email renderer and the first
working terminal client for the opinionated Warm/Cold/Spam workflow specified
in [`../../spec/tui-workflows.md`](../../spec/tui-workflows.md).
The exact implementation boundary is tracked in
[`../../spec/tui-implementation-status.md`](../../spec/tui-implementation-status.md).
The Linux worker threat model and failure policy are documented in
[`../../spec/tui-render-isolation.md`](../../spec/tui-render-isolation.md).

Build the client and all three isolated workers, then run the client. By
default it opens the platform's per-user Lizard profile (`$XDG_DATA_HOME/lizard-mail`
or `~/.local/share/lizard-mail` on Linux):

```sh
cargo build --locked \
  -p lizard-mail-tui --bins \
  -p lizard-mail-backend --bins
cargo run -p lizard-mail-tui
```

Use `--profile /path/to/profile` for a portable, test, or recovery profile.
The first run opens an account-connection form. It stores passwords or access
tokens through the backend credential manager, starts header-first IMAP
synchronization in the isolated worker, then builds a verified full local copy
in bounded batches while the header projections are already usable, and then
offers contact suggestions.
Configured IMAP accounts synchronize automatically at startup and every five
minutes in disposable workers; press `A` from the ordinary client to add, edit,
synchronize on demand with `s`, diagnose, or remove accounts. Account removal
requires confirmation and does not delete mail from the remote server.

Cargo places the four executables together, which is also the portable release
layout. Native packages install only `lizard-mail-tui` in `PATH` and place the
workers under `/usr/libexec/lizard-mail`. See
[`../../packaging/README.md`](../../packaging/README.md) for the reproducible
tarball, Debian and RPM artifacts.

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

The normal CLI never parses sender-authored HTML in its main process. On Linux
x86-64 it invokes a fresh worker for each distinct message/terminal width. The
worker must enter an empty Landlock ruleset, a seccomp filter, and fixed
address-space/CPU/file limits before reading the request. It receives pipes,
not a terminal, and returns semantic text over a length-prefixed protocol. The
parent validates every line, span, style, reference, control character and
output budget before Ratatui sees it. If any boundary is unavailable or the
worker crashes, times out, or returns malformed output, the reader displays the
backend's safe plain-text body; it never retries HTML in-process.

The rendering core itself performs no network or filesystem operations. Remote
and embedded images become labelled placeholders; links become inert numbered
references; forms and active content are omitted. Author colors and layout CSS
are ignored so that hostile mail cannot make text invisible against the
terminal theme. `HtmlRenderer` remains public for conformance tests and
controlled embedders; applications handling hostile mail should use
`IsolatedHtmlRenderer` or an equivalent process boundary.

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
