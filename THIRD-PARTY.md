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

`vendor/async-imap` contains a hardened fork of Chatmail's async-imap 0.12.0,
pinned at commit `31fde98fceb5b9bde726807419992f8d84b1f193`. Upstream offered
the work under `MIT OR Apache-2.0`; this vendored copy selects Apache-2.0 and
includes the license text as `vendor/async-imap/LICENSE`. Local changes and
provenance are recorded in `vendor/async-imap/UPSTREAM.md`.
