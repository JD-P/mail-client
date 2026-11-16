# OpenPGP differential conformance harness

This test-only crate compares rPGP's output with GnuPG after giving both
implementations the same semantic inputs and the same random byte stream.  It
exists outside the application workspace so none of its dependencies or unsafe
test instrumentation can enter a production build.

The positive differential scope is deliberately small and modern:

- RSA-3072 with SHA-256 detached signatures;
- RSA-3072 PKCS#1 v1.5 session-key wrapping; and
- AES-256 OpenPGP CFB with an integrity-protected SEIPDv1 container.

RFC 9580 Ed25519, X25519 and SEIPDv2 are covered by the upstream rPGP known-
answer vectors.  GnuPG 2.4.7 cannot act as an independent oracle for those
packet formats: its `--force-aead` format is the incompatible LibrePGP/GnuPG v5
format.  Do not add legacy DSA, ElGamal, IDEA, 3DES, CAST5, SHA-1-signature or
unauthenticated SED positive cases here.

The C interposer deliberately destroys GnuPG's randomness.  Its constructor
terminates the process unless the harness supplies the exact test-only opt-in
value.  Never preload it outside this harness.

## Deterministic matrix

The exact-output test requires Linux, a C compiler, and exactly GnuPG 2.4.7.
It is ignored during ordinary project tests:

```sh
cargo test --manifest-path tests/openpgp-conformance/Cargo.toml --locked
cargo test --manifest-path tests/openpgp-conformance/Cargo.toml --locked \
  --test differential -- --ignored --nocapture
```

Set `OPENPGP_CONFORMANCE_GPG` or `CC` to override the executable paths.

## Differential fuzzer

Install `cargo-fuzz`, then run the fuzzer from its manifest directory.  The
harness generates one disposable RSA key per fuzzer process and reuses it for
all cases.  Each input selects a primitive, a deterministic random-stream
offset and up to 8 KiB of payload.  GnuPG is executed once per case, so this is
an intentionally slow fuzzer; use a single worker and retain its corpus.

```sh
cargo install cargo-fuzz --locked
cd tests/openpgp-conformance/fuzz
cargo fuzz run differential --sanitizer none -- \
  -max_len=8194 -timeout=30 -workers=1
```

`--sanitizer none` lets the pinned stable Rust toolchain build the target.  A
nightly toolchain may instead use libFuzzer's supported sanitizers.

The fuzzer treats any GnuPG failure or byte mismatch as a crash and preserves
the reproducing input in `fuzz/artifacts/differential/`.
