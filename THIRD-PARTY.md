# Third-party sources

`vendor/wr` contains the pinned Mozilla WebRender/SWGL source subset. Original
per-file notices are retained; the Mozilla Public License 2.0 text is included
in `LICENSE-MPL-2.0.txt`. Standalone workspace/Glean adjustments are identified
in `spec/standalone-adapters.json`. Lizard's `LICENSE` covers Lizard's own code.

Other dependencies are acquired by Cargo using Cargo.lock and retain their own
package licenses/notices. They are not relicensed by Lizard. System FreeType and
approved OS fonts are runtime/build dependencies, not bundled font binaries.
Firefox, geckodriver and Verus releases are downloaded separately by the optional
checksummed bootstrap tool; their upstream licenses continue to apply.

`src/software_raster.rs` adapts the fixed-point analytic edge stepping used by
Skia's anti-aliased path rasterizer into bounded safe Rust. Skia is Copyright
(c) 2011 Google Inc. and is distributed under its BSD 3-Clause license, included
as `LICENSE-SKIA.txt`.

`vendor/async-imap` contains a hardened fork of Chatmail's async-imap 0.12.0,
pinned at commit `31fde98fceb5b9bde726807419992f8d84b1f193`. Upstream offered
the work under `MIT OR Apache-2.0`; this vendored copy selects Apache-2.0 and
includes the license text as `vendor/async-imap/LICENSE`. Local changes and
provenance are recorded in `vendor/async-imap/UPSTREAM.md`.

`crates/mail-backend/src/popular_domains.txt` contains the MISP Warning Lists
`tranco10k` snapshot version `20261005` (10,000 domains), derived from the
Tranco popularity ranking. MISP Warning Lists publishes the list under the
CC0 1.0 Universal public-domain dedication. The snapshot is bundled so sender
identity checks never disclose correspondence through a network lookup.

`tests/fuzz-seeds` contains inert sanitized structural derivatives of Mailgun's
transactional email templates (commit
`e05e59e8c1e0fa7ffbacc7a165a609fd37c590b5`) and Ted Goas's Cerberus hybrid
template (commit `af3cec9dd12fbbea0c6e9a1b0bf82a0479726957`). Both upstreams
use the MIT license. Their license texts, exact provenance and sanitization
notes are retained beside the seeds. Tests never fetch the upstream templates
or any remote resource.
