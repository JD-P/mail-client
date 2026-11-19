# Dependency security preflight

This is a reproducible dependency-status snapshot, not an adversarial finding
and not an assertion that the dependency graph is vulnerability-free.

## 2026-11-19 scan

`cargo-audit 0.23.0` scanned the workspace lockfile against RustSec
advisory-database commit `074ea9a7ed619f511b5b7374c7a97e98d1e98be4`,
updated 2026-11-19. The command was:

```sh
cargo audit --json
```

It reported two vulnerabilities, both in the current `pgp 0.21.1` dependency
graph:

| Advisory | Locked package | Path | Status |
|---|---|---|---|
| `RUSTSEC-2023-0071` | `rsa 0.9.10` | `pgp -> rsa` | Unresolved upstream; patched RSA is `>=0.10.0` |
| `RUSTSEC-2026-0387` | `crypto-bigint 0.5.5` | `pgp -> elliptic-curve/cx448 -> crypto-bigint` | Unresolved upstream; patched crypto-bigint is `>=0.7.6` |

Both advisories concern timing or microarchitectural leakage from secret-key
arithmetic. Lizard is not an RSA network server and does not expose a direct
remote decryption/signing timing oracle, which materially limits the published
Marvin-attack scenario. The pure-software OpenPGP provider does perform local
secret-key operations, however, so these are real unresolved dependency risks,
not false positives.

The latest crates.io rPGP release and upstream rPGP commit
`52750e6f5ca849485c368e0a4acf9a189e9a558f` still select `rsa 0.9.10`, the
0.13 RustCrypto elliptic-curve family and `cx448 0.1.1`. RSA 0.10 changes its
integer, digest, RNG and signature APIs; the elliptic-curve fix requires a
coordinated curve-family/cx448 migration. Silencing the advisories with a
version override would not compile, and locally inventing cryptographic
backports merely to obtain a clean scanner result would be unsafe. The proper
remediation is an audited rPGP dependency-stack migration followed by the
existing GnuPG differential conformance and fuzz harness.

The scan also reported `RUSTSEC-2026-0253` for `lru 0.16.4`, reached through
Tantivy 0.26.2. The advisory requires a panicking key destructor during
`LruCache::pop()` followed by continued use after `catch_unwind`. Tantivy's
reachable store cache uses `usize` keys and owned byte blocks, and the
maintained client code does not catch unwinding panics, so the advisory's
memory-corruption preconditions are not reachable in this use. It remains
tracked until Turso and Tantivy can converge on a patched LRU dependency.

RustSec additionally emitted eighteen `unmaintained` warnings. These are
maintenance signals rather than demonstrated vulnerabilities and include
transitive dependencies from the graphical renderer, Turso, keyring and parser
stacks. They should be considered during dependency upgrades, without being
misrepresented as eighteen security defects.

Any later scan must record its advisory-database commit because this snapshot
is time-sensitive.
