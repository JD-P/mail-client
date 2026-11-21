# Linux release artifacts

Each tagged Lizard Mail release publishes four separate assets:

- `lizard-mail-VERSION-linux-x86_64-musl.tar.gz` — portable archive;
- `lizard-mail_VERSION-1_amd64.deb` — Debian-family package;
- `lizard-mail-VERSION-1.x86_64.rpm` — RPM-family package; and
- `SHA256SUMS` — checksums for the three payloads.

There is deliberately no loose `lizard-mail-tui` download. A functioning and
secure installation is a matched set of four executables: the interactive
client plus the HTML-render, IMAP-sync and ZIP-inspection workers. Publishing
the client alone would invite version skew at the process boundaries.

The portable archive keeps all four executables beside one another. Run it as:

```sh
tar -xzf lizard-mail-*-linux-x86_64-musl.tar.gz
cd lizard-mail-*-linux-x86_64-musl
./lizard-mail-tui
```

The client uses `$XDG_DATA_HOME/lizard-mail` or
`~/.local/share/lizard-mail` by default. Pass `--profile /path/to/profile` for
a portable, test, or recovery profile.

The Debian and RPM packages install `/usr/bin/lizard-mail-tui` and keep the
internal workers outside `PATH` under `/usr/libexec/lizard-mail/`. Worker
discovery first checks beside the running executable (Cargo and portable
layouts), then Cargo's integration-test directory, and finally the fixed
`libexec` directory. Every resolved path is canonicalized before execution.

The artifacts target Linux x86-64 using musl and contain no dynamic-library
dependencies. The disposable workers still require a kernel with Landlock ABI
6 for their complete production sandboxes; unsupported kernels fail closed.

## Reproducible build

The release gate uses a digest-pinned Rust 1.100.0 container and exact Debian
package versions. After Cargo verifies the sources in `Cargo.lock`, the actual
release build runs without network access. It builds in two deliberately
different source and target paths and compares every resulting byte, including
the tarball, Debian package, RPM package and checksum file.

Each disposable source copy is reduced to a virtual workspace containing only
the backend, TUI, verified kernel and their vendored mail dependencies. This
keeps the CLI release independent of the graphical renderer's patched graphics
toolchain without changing any source compiled into the four executables. Its
dependency graph is independently pinned by `packaging/Cargo.cli.lock`.

Run the same gate locally with Docker:

```sh
SOURCE_DATE_EPOCH=$(git log -1 --format=%ct) \
  packaging/run-reproducible-build.sh --output release
```

The GitHub workflow inspects package contents, installs the Debian and RPM
payloads in clean containers, runs every executable's version probe, checks
the standalone seccomp probes, verifies `SHA256SUMS`, and emits GitHub build
provenance attestations. Tagged `vVERSION` builds become permanent GitHub
Release assets only when the tag, checkout and crate versions all agree.
