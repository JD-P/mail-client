# P3·B — default worker discovery under cargo 1.100 test layout

The reviewed repository's own guard test
`security_evidence::archive_security_reads_directory_metadata_but_never_inflates_entries`
fails because default worker discovery (`crates/mail-backend/src/worker_path.rs`)
does not resolve under the artifact layout of the pinned toolchain
(`rust-toolchain.toml` channel `1.100.0`).

`results.txt` retains the failing assertion and a probe that contrasts default
discovery with an explicit `ArchiveIsolationConfig`:

- the integration test binary runs from
  `target/debug/build/lizard-mail-backend/<hash>/out/`;
- `worker_path::discover` checks beside the executable, then only when the
  directory is named `deps` one level up, then `/usr/libexec/lizard-mail`;
- none of those locations contain the archive worker in this layout, so
  `Backend::default` ZIP inspection fails with
  `archive worker is unavailable` and the finding degrades to `uninspectable_archive`;
- passing the built worker path explicitly produces
  `ArchiveInspection { state: Complete, ... }` with the `documents/invoice.pdf.exe`
  entry that the guard test expects.

This is an engineering/validation defect rather than a scored vulnerability:
the default path fails safe (uninspectable archive warning), production
portable and package layouts place workers beside the main binary or in
`/usr/libexec/lizard-mail`, and the failing test deliberately surfaces the
gap. It is retained because the repository test suite is red at the reviewed
commit.

Reproduce with the pinned toolchain:

```sh
cargo test -p lizard-mail-backend --test security_evidence \
  archive_security_reads_directory_metadata_but_never_inflates_entries
```
