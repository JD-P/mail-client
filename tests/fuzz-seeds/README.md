# Sanitized production-template fuzz seeds

These inert local fixtures preserve the characteristic nested-table, inline
style and responsive structures of permissively licensed production email
templates. They are inputs to `tools/fuzz_conformance.py`, not examples of
Lizard-authored markup.

Every seed was deliberately sanitized before being checked in:

- remote images, stylesheets and destinations were removed;
- links use local fragments;
- scripts, forms, event handlers, VML and tracking content were removed;
- identifying message content was replaced with neutral test prose; and
- three inert `FUZZ_SLOT_*` comments mark bounded insertion points.

The seeds set `scrollbar-width:none` on the root. Gecko otherwise reserves
browser scrollbar chrome for long messages, while Lizard correctly renders
into a frontend-owned scrolling surface without browser chrome. Content remains
scrollable; this only removes a comparison-harness width artifact.

The generator validates the final bytes and refuses active content, external
HTTP(S), CSS `url()`, imports, embedded browsing contexts and event handlers.

## Provenance

- `mailgun-action.html` and `mailgun-basic.html` are sanitized structural
  derivatives of Mailgun's `transactional-email-templates`, commit
  `e05e59e8c1e0fa7ffbacc7a165a609fd37c590b5`, MIT license. See
  `LICENSE-MAILGUN.txt`.
- `cerberus-hybrid.html` is a sanitized structural derivative of Ted Goas's
  Cerberus hybrid template, commit
  `af3cec9dd12fbbea0c6e9a1b0bf82a0479726957`, MIT license. See
  `LICENSE-CERBERUS.txt`.

The upstream source bytes are not fetched during tests. These reviewed,
sanitized bytes are the complete seed corpus supplied independently to Gecko
and Lizard.
