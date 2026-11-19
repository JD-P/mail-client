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
A successful Verus run on this renderer kernel currently reports **10 verified,
0 errors**, comprising six functions and their internal proof obligations.

`crates/verified-kernel/src/lib.rs` is a second single-source executable kernel
shared by the mail backend, terminal renderer and vendored IMAP adapter:

| Routine | Checked postcondition | Runtime caller |
| --- | --- | --- |
| `charge_usize`, `charge_u64`, `charge_u32` | Accepted totals are mathematically exact, within the limit and cannot have wrapped; every in-limit sum succeeds | renderer output validation, IMAP command/FETCH budgets, blob and storage accounting, heuristic runtime |
| `bounded_read_window` | A returned OpenPGP read window is nonempty, no larger than the buffer and cannot cross the one-byte sentinel | software OpenPGP plaintext inspection |
| `repeat_cost` | Successful bounded-loop cost multiplication is exact and within its limit | heuristic static structural-cost calculation |
| `materialize_bytes` | Materialized storage remains within its reservation and advances by the exact byte count | blob and IMAP body writes |
| `reservation_commit_allowed` | A commit cannot publish more bytes than were materialized, and materialization cannot exceed reservation | storage reservation commit |
| `thread_candidate_allowed` | An unknown sender can never be admitted to a known thread | header and normalized-subject thread candidate validation |
| `submission_transition` | SMTP outbox transitions follow the explicit graph; sent, ambiguous and cancelled are terminal | outbox compare-and-set operations and interrupted-send recovery |
| `imap_mutation_transition` | Durable IMAP transitions follow the explicit graph; applied and cancelled are terminal | mutation compare-and-set operations |

That kernel reports **16 verified, 0 errors**. Together both commands report
**26 verified obligations across sixteen executable functions**. This does not
mean 26 independently verified modules or a verified application.

The heuristic proof boundary is deliberately precise: all structural and text
work counters use verified fail-closed arithmetic, static loop multiplication
is verified, and runtime structural execution is capped by the compiler's
calculated maximum. The Rust match which maps each interpreter node to its
structural cost is reviewed and regression-tested but is not yet a recursive
Verus proof of the entire interpreter. Any future mismatch therefore fails
closed at runtime rather than granting extra work.

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
and deeper composition of the now-verified per-transition accounting across a
complete message. SQL transaction isolation, external `Read` implementations,
URL/MIME/crypto parsers and filesystem measurements remain trusted boundaries;
their outputs are revalidated before entering the verified transitions. Pixel
comparisons against Gecko constrain the behavioral specification; they do not
prove that the specification is safe or complete.
