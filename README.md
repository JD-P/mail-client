# Lizard

A Rust HTML/CSS email frontend feeding Mozilla WebRender + SWGL. It independently
parses the original UTF-8 HTML, applies a restricted cascade, lays out static
message content, and emits pixels plus semantic/link metadata.

This is a working initial engine, **not a finished implementation of the entire
requested profile**. All 155 requested Support/Bounded entries are mapped in
[implementation status](docs/implementation-status.md), with a machine-readable
version in `spec/implementation-status.json`. “Implemented” denotes executable
bounded behavior, not complete standards conformance. The original requested
policy and 308-entry feature audit remain separate design inputs under `spec/`.
No empirical inbox-coverage claim is made.

## Build and render

The runnable host/sandbox currently targets **Linux x86-64**. Install Rust
1.100.0, a C++ compiler, pkg-config, system FreeType development files and DejaVu
core fonts. Liberation fonts provide the Arial/Helvetica, Times and Courier
aliases used by the checked environment; those aliases fall back to the generic
DejaVu families if Liberation is absent. Other platform font resolvers and broad
CJK/emoji fallback are unfinished. No sender-supplied font files are loaded.

```sh
cargo build --locked --release
target/release/lizard sandbox-self-test
target/release/lizard render tests/fixtures/text-basic.html message.png 800 600 trace.json
```

FreeType must be discoverable through pkg-config. The build deliberately rejects
an absent system package rather than letting freetype-sys silently build its
bundled fallback. Native/font versions affect exact pixels. Cargo.lock pins the
application dependency graph; rendering sources are vendored.

`render INPUT OUTPUT [WIDTH HEIGHT TRACE SCROLL]` uses the sandboxed worker.
SCROLL is in CSS pixels. The optional trace contains the DOM, computed styles and
layout scene for diagnostics. Ordinary rendering sends only bounded semantic
metadata, avoiding the cost of full diagnostic serialization.

## Architecture and integration

The host launches a fresh disposable worker for a render job. Before untrusted
HTML/CSS/shaping/codecs/SWGL run, the worker loads approved OS font bytes, closes
inherited descriptors and installs a Linux x86-64 seccomp syscall allowlist.
Filesystem opens, networking, process exec, tracing and display/GPU access are
unavailable. Thread-style clone is constrained; clone3 returns ENOSYS so libc
uses the inspectable legacy operation. The worker also installs checked
address-space/CPU/core-dump limits. Failure to install the sandbox or limits is
an error. Namespace isolation was unavailable in this environment; this is not
Chrome's full layered sandbox.

The host owns dimensions, paths, expected RGBA length, reply limits and an
8-second wall deadline. Nonblocking pipes cover both job writes and reply reads;
errors kill and reap the child. Pixels cross as fixed-size raw RGBA, with PNG
encoding in the host. Child metadata is untrusted input for the application.
The syscall/transport/graphics adapters contain explicitly separate unsafe code.
The core/DOM/CSS/style/text/layout/resource modules forbid local unsafe Rust.

The library's `paint::Painter` retains its display list, scene, glyph resources
and WebRender caches. Call `set_scene` after layout and `frame(scroll_app_units)`
for scrolling; layout and initialization do not repeat for each frame. The CLI
is deliberately a one-shot conformance tool. A client embedding this API should
keep it inside a message worker and discard that worker between messages; a
persistent interactive IPC session is not implemented by the CLI yet.

The project has no account/credential store, MIME reader, network fetcher,
mailbox/application UI, OS link launcher or send-mail API. Resources must be
explicitly supplied for the current job, or be allowed literal raster data.
External/CID resource keys confer no fetching authority. Link fragments,
logical readable text and scoped accessibility labels/roles are emitted for
integration. Trusted focus indication, canonical destination display, validated
user-gesture navigation/compose actions and native accessibility/selection UI
belong to the surrounding application. Development `worker` mode is explicitly
unsandboxed; normal `render` uses `worker-stdio` through the host transport.

## Independent Gecko conformance

```sh
python3 -m pip install -r requirements-oracle.txt
python3 tools/bootstrap.py --only firefox
python3 tools/bootstrap.py --only geckodriver
python3 tools/conformance.py --binary target/release/lizard \
  --firefox .tools/firefox/firefox --geckodriver .tools/geckodriver
```

The bootstrap verifies pinned archive SHA-256 checksums from
`spec/toolchains.json` before extraction. The oracle requires stock Firefox
160.0 build 20261104181552 and geckodriver 0.37.1, forces SWGL, fixes DPR/fonts
and blocks document scripts and external HTTP/S through its test preferences.
It loads original fixture files directly. Lizard never preprocesses input for
Gecko. Raw source hashes, independent DOM/layout traces, screenshots, diffs and
an HTML report are saved under `results/conformance`.

The default gate requires matching independently parsed DOMs, exact app-unit
geometry for element boxes Lizard emits, exact alpha, and exact document pixels.
DOM checks include node kinds, attributes and tree relationships. Missing
element boxes remain outside geometry probe coverage.

Six isolated raster-enlargement fixtures explicitly allow RGB differences only
inside fixed fixture-authored image rectangles: at most 32/255 per channel at
any pixel, and at most 3/255 mean error in each channel over each rectangle.
These are initial test-policy allowances for media filtering, not a claim of
bit-equivalent media rendering. No rectangle is inferred from Lizard's output.
All surrounding pixels remain exact, as do DOM, alpha and geometry. The report
separates exact passes from cases accepted with an image allowance and retains
the original diffs. `--strict-images` disables those allowances. The 1:1 PNG
control has no allowance, and the Rust source-pixel test checks decoded RGBA.

The runner exits nonzero if cases still fail the selected policy.
`--reuse-oracle` checks raw bytes, viewport, oracle code and font/FreeType
fingerprints. A small synthetic fixture passing does not establish property-wide
or inbox coverage. Test the comparison policy itself with
`python3 -m unittest discover -s tools -p 'test_*.py'`.

Both rendering source sets use Firefox tag `FIREFOX_160_0_RELEASE`, Git revision
`2887d9de1f69c0e9776413da80e7ba0d1225dd9b`; the official binary records Mercurial
revision `d84e7a6936554efe26097d9d9b24a0e11330e630`. Run
`python3 tools/check_upstream.py` to check the 245 pinned rendering files and
reject unexpected files. Standalone Cargo/Glean adjustments are separately
hashed in `spec/standalone-adapters.json`.

## Verus and checks

```sh
rustup toolchain install 1.99.1 --profile minimal
python3 tools/bootstrap.py --only verus
.tools/verus-x86-linux/verus --crate-type lib src/verified.rs
cargo test --locked --release
cargo fmt --package lizard --check
python3 tools/check_upstream.py
```

Six executable kernel functions in `src/verified.rs` pass Verus 0.2026.11.02.8bf68ee:
budget debit, bounded addition, buffer containment, RGBA length, alpha
premultiplication and table occupancy interval updates. The verifier reports
10 verified obligations and zero errors. Cargo erases contracts from those
same definitions; no duplicate model bodies, assume, admit or external_body
are used. See [verification boundaries](docs/verification.md).

The remainder is ordinary Rust, arranged around indexed owned arenas, explicit
budgets, typed lengths and fixed-point geometry for later contracts. Parsing,
shaping/Unicode, codecs, native fonts, WebRender/SWGL, serialization, OS adapters
and their specifications are not verified. This is not a proof of whole-engine
security, layout equivalence, termination, memory bounds or availability.

## Known conformance gaps

The retained report includes a one-app-unit table column distribution difference,
image upsampling/filter differences, native list
markers, rounded/mixed borders, skip-ink and subpixel text/ellipsis details,
gradient/opacity rounding, and other cases listed in implementation status.
Table border groups/joins, some inline formatting and opacity, percentage-height
interactions, complete decoration styles, arbitrary Boolean media grammar,
language/font fallback and application accessibility/navigation need more work.
Resource exhaustion returns an error; a trusted readable fallback UI is an
application responsibility.

Third-party rendering sources retain their Mozilla Public License notices;
Lizard's own code is MIT licensed. To create a source/results archive, run
`python3 tools/package.py /path/to/lizard-source.zip`.

For fresh-worker timing on one allowed CPU, run
`python3 tools/benchmark.py --one-cpu --binary target/release/lizard`.
The included `results/benchmark.json` distinguishes maximum-process RSS from
aggregate application memory and documents the cloud-hardware limitations.
