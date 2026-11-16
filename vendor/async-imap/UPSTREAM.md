# Upstream provenance

- Project: `async-imap`
- Source: <https://github.com/chatmail/async-imap>
- Upstream version: `0.12.0`
- Upstream commit: `31fde98fceb5b9bde726807419992f8d84b1f193`
- Vendored version: `0.12.0-lizard.1`
- Vendored on: 2026-11-16
- Selected license: Apache License 2.0

Upstream distributes this source under `MIT OR Apache-2.0`. Lizard selected
the Apache-2.0 option. The unmodified Apache license text is in `LICENSE`.
Copyright and authorship remain with the upstream contributors for upstream
code; Lizard's changes are also distributed under Apache-2.0.

## Local hardening

- Matching tagged completion is mandatory; `NO`, `BAD`, and premature EOF are
  errors for streaming and collected command APIs.
- A dropped streaming or collected command is drained before the next command,
  preventing response contamination after cancellation or partial consumption.
- Protocol payloads, passwords, bearer tokens, and message data are not written
  to trace logs or parser error strings.
- Every tagged and untagged command rejects CR/LF injection.
- APPEND accepts legal unsolicited responses before the continuation prompt.
- IDLE handles tagged rejection without panic or blocking and distinguishes EOF
  and I/O failure from a caller-requested interruption.
- Response allocation grows in 4 KiB blocks. Responses default to a 64 MiB
  limit, configurable with `Connection::set_max_response_size`.
- `Session::uid_fetch_body_to` streams a complete message to an async writer
  through bounded partial `UID FETCH` requests instead of retaining it whole.
- Parenthesis nesting defaults to 128 and is checked before recursive parsing,
  configurable with `Connection::set_max_response_nesting`.
- The bounded unsolicited-response channel emits `UnsolicitedResponse::Overflow`
  when loss occurs instead of silently presenting an incomplete event stream.
- Deprecated unsafe pin-projection macros were replaced with safe projection of
  the library's explicitly `Unpin` connection types.

The audit regressions are retained in `tests/review_regressions.rs`.
