# Verification boundaries

`src/verified.rs` contains executable Rust inside `verus!`. Cargo compiles those
same bodies with the contracts erased. No alternate model implementation is
substituted at runtime. The checked tool versions and download checksums live in
`spec/toolchains.json`; the application dependency graph is fixed by Cargo.lock.

| Routine | Checked postcondition | Runtime caller |
| --- | --- | --- |
| `debit` | Exact subtraction on success; failure if cost exceeds remaining; never increases the balance | `Budget::charge` |
| `add_coord` | Successful sum is exact and within ±60,000,000 app units; succeeds for in-range operands and result | checked layout additions |
| `contained` | Equivalent to mathematical offset + length ≤ capacity, including overflowing machine-sized sums | buffer boundary API |
| `rgba_length` | Nonzero dimensions, stride ≥ width × 4, exact stride × height, bounded by caller limit; completeness for valid descriptors | image/surface validation |
| `premultiply_channel` | Exact rounded channel × alpha / 255, output ≤ channel and alpha, correct transparent/opaque endpoints | native image upload |
| `mark_columns` | Vector length unchanged; selected columns become max(old, until); outside columns unchanged; failed ranges leave the entire vector unchanged | table occupancy |

The table routine includes a verified loop invariant and termination measure.
A successful Verus run currently reports **10 verified, 0 errors**, comprising
six functions and their internal proof obligations. This does not mean ten
independently verified modules or a verified application.

The core, DOM adapter, CSS adapter, style, text, layout and raster-resource
modules forbid local unsafe Rust. Fixed-point geometry, indexed owned arenas,
typed CSS lengths, explicit limits and ordinary loops are intended to make
further contracts practical. They are not themselves proofs. In particular,
work accounting is incomplete inside dependencies and is not yet a proof of
global time or memory bounds. The worker's OS limits and the host deadline
remain necessary backstops.

Unverified or trusted boundaries include Verus/vstd specifications and solver,
Rust and C++ compilation, HTML5ever/cssparser/color parsing, Rustybuzz/Unicode
algorithms, approved local font parsing and FreeType, raster codecs,
WebRender/SWGL, serde, the kernel, and the small unsafe syscall/graphics adapters.
The system FreeType development package is required at build time to prevent
freetype-sys silently choosing its bundled fallback source.

Next useful proofs are composition of table grid/span bounds, fixed-point CSS
expression evaluation, scene validation implying all native API preconditions,
and resource accounting across a complete message. Pixel comparisons against
Gecko constrain the behavioral specification; they do not prove that the
specification is safe or complete.
