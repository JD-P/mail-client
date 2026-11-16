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
