# Terminal HTML-email rendering profile

The Ratatui renderer consumes the same untrusted HTML-email input as the
graphical renderer, but its conformance target is semantic terminal output—not
browser layout or pixels. Terminal cells cannot represent CSS geometry, fonts,
paint, or raster images faithfully.

## Preserved

- HTML5 tree repair and decoded text
- paragraphs, sections, headings, quotations, horizontal rules, and line breaks
- bold, italic, underline, deletion, small text, and code-like text
- preformatted whitespace with Unicode-cell wrapping
- ordered, reversed, alphabetic, Roman, and nested lists
- description lists
- table captions, headers, cells, `colspan`, and `rowspan`
- link text plus numbered, canonical destination references
- image alternative text plus inert image metadata
- `hidden`, `aria-hidden`, inline `display:none`, `visibility:hidden`, and
  `mso-hide:all`
- inline font weight/style, text decoration, whitespace, transform, and
  alignment where Ratatui has a meaningful equivalent

Tables become Unicode/ASCII grids when columns remain readable. At narrow
widths they become stacked `Header: Value` records. This is an intentional
responsive semantic transformation.

## Reduced or omitted

- Raster and background images are never decoded, fetched, or converted to
  terminal art. They become labelled placeholders.
- Forms become one inert omission notice. Scripts, frames, embedded objects,
  SVG, MathML, media, canvases, templates, and active metadata are removed.
- External and embedded stylesheets are ignored. Author colors, backgrounds,
  fonts, dimensions, margins, floats, positioning, gradients, and other visual
  layout properties do not override the terminal application's theme.
- Bidirectional language text remains in logical order for the terminal.
  Explicit bidi embedding, isolate, and override controls are exposed as
  visible tokens so they cannot silently reorder identities or destinations.
- Relative and blocked-scheme links are reported but are not navigation
  authority. The terminal client's trusted action broker accepts only parsed
  absolute HTTP(S) references and disables navigation entirely in
  interstitial/restricted message views.

## Resource and capability boundary

The crate owns no network, filesystem, process, terminal-driver, MIME, or image
capability. Limits cover input bytes, parser-token preflight, copied DOM nodes,
depth, attributes, decoded text, links, images, table cells, output lines, and
output cells. The caller receives owned Ratatui lines and bounded metadata.
