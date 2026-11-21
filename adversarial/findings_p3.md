# Pass 3 — isolated worker platform detection and default worker discovery

- **Date:** 2026-11-20 (local); retained session interval
  `2026-11-20T23:22:03.447Z`–`2026-11-21T00:51:56.982Z`.
- **Subject:** clean commit
  `7c1a6683fbb7cd24e8779fc9b2c9c9b711e1e525`, equal to `origin/main` before
  this pass created `adversarial/p3/`.
- **Harnesses:** `adversarial/p3/imap-worker-landlock/`; retained output is
  `results.txt`, `engine-sync-failure.txt` and
  `corrected-policy-verification.txt`. The second retained case is in
  `adversarial/p3/worker-discovery/results.txt`.
- **Method:** built the CLI release workspace with the pinned Rust 1.100.0
  toolchain (the same transformation as `packaging/reproducible-build.sh`),
  ran the complete `lizard-mail-backend` and `lizard-mail-tui` suites, then
  bisected the isolated IMAP worker's Landlock policy in disposable copies.
  The reviewed checkout was not modified.
- **Disposition:** **P3-A confirmed at the reviewed commit.** P3-B is a
  retained engineering/validation defect that is reported but not scored
  (it fails safe). The product source was not modified by this review.
- **Resources:** the single confirmed finding is charged the full Pass-3
  search budget: 896,727 input / 75,647 output / 127,906 reasoning /
  109,479,296 cache-read / 0 cache-write tokens (1,100,280 billed tokens) at
  a harness-recorded session cost of **$1.974953**. The unscored P3-B
  observation shares the same budget.

---

## 1. Executive summary

| # | Finding | Intended boundary | Observed behavior | Class |
|---|---|---|---|---|
| **P3-A** | The isolated IMAP synchronization worker must start under a fully enforced Landlock ABI 6 ruleset when the kernel supports it. | A capable kernel or an expected `/etc/hosts`-class file must not be misclassified as partial enforcement. | `enter_landlock` applies the directory-only `ReadDir` right to regular-file rules; `landlock` 0.4.7 drops the incompatible right and reports `PartiallyEnforced`, so the worker always fails closed with `Landlock sandbox was not fully enforced` on ordinary hosts. `IsolatedImapAccountEngine::sync_once` then fails with `isolated IMAP worker protocol failed: early eof`. | **medium availability defect in a fail-closed security control**; not attacker-triggerable |
| **P3-B** | Default worker discovery must locate the separately installed worker in every layout the repository supports. | Integration tests and embedders using the default archive configuration should find the archive worker. | With the pinned cargo 1.100.0 artifact layout, integration test binaries run from `target/<profile>/build/<pkg>-<hash>/out/`, which neither the sibling check nor the `deps` fallback covers; `Backend::default` ZIP inspection reports `archive worker is unavailable` and the repository's own guard test fails. | **engineering/validation defect** (safe `uninspectable_archive` fallback; production package layouts unaffected); not scored |

---

## 2. P3-A — every Landlock-capable host is rejected as partially enforced

### 2.1 The read-path rules mix directory and file access rights

`enter_landlock` starts with one read right set and applies it to a mixture of
directories and regular files:

```rust
// crates/mail-backend/src/imap_worker.rs:902
let read_access = AccessFs::from_read(abi) & !AccessFs::Execute; // ReadFile | ReadDir
...
for path in [
    "/etc/hosts", "/etc/nsswitch.conf", "/etc/resolv.conf",
    "/usr/share/zoneinfo", "/proc/self", "/proc/meminfo", "/proc/cpuinfo",
    "/sys/devices/system/cpu", "/dev/urandom",
] {
    if Path::new(path).exists() {
        created = created.add_rule(PathBeneath::new(PathFd::new(path)?, read_access))?;
    }
}
```

`/etc/hosts`, `/etc/nsswitch.conf`, `/etc/resolv.conf`, `/proc/meminfo`,
`/proc/cpuinfo` and `/dev/urandom` are regular files on an ordinary Linux
system. The pinned `landlock` 0.4.7 crate handles that mismatch explicitly: for
a regular file it intersects the requested rights with the file-compatible
subset, drops `ReadDir`, and records a partial compatibility result
(`landlock-0.4.7/src/fs.rs:297-317`,
`PathBeneath::try_compat_inner` -> `CompatResult::Partial`). That partial
result downgrades the whole ruleset to `RulesetStatus::PartiallyEnforced`
(`landlock-0.4.7/src/compat.rs:360-368`).

The worker then applies its own strict check:

```rust
// crates/mail-backend/src/imap_worker.rs:987
if status.ruleset != RulesetStatus::FullyEnforced || !status.no_new_privs {
    return Err(format!("Landlock sandbox was not fully enforced: {status:?}"));
}
```

so the worker exits before reading its protocol request. The failure is
over-restrictive (fail closed), not an escape; the security consequence is
that the intended isolation boundary cannot be used at all.

### 2.2 Reproduction on kernel 6.12.117+deb13-amd64

The retained harness builds the worker through the CLI release workspace and
records (full text in `adversarial/p3/imap-worker-landlock/results.txt`):

```text
$ lizard-mail-sync-worker --sandbox-self-test <profile>
isolated IMAP worker failed: Landlock sandbox was not fully enforced:
RestrictionStatus { ruleset: PartiallyEnforced, no_new_privs: true,
landlock: Available { effective_abi: V6, kernel_abi: None },
log_same_exec: true, log_new_exec: false, log_subdomains: true,
all_threads: false }
exit 1

$ cargo test -p lizard-mail-backend --test imap_worker worker_sandbox_is_fail_closed
thread 'worker_sandbox_is_fail_closed' panicked at
crates/mail-backend/tests/imap_worker.rs:83:9:
sandbox failed for an unexpected reason: ... PartiallyEnforced ...
test result: FAILED
```

The guard test accepts only two shapes: a fully enforced ruleset with all
eight denial properties true, or a failure whose stderr mentions
`Landlock sandbox was not fully enforced` *and* `NotImplemented`/`NotEnabled`
(`crates/mail-backend/tests/imap_worker.rs:81-88`). A capable kernel with a
partially enforced ruleset matches neither, so the repository's own suite is
red at the reviewed commit.

A standalone bisection copied into the disposable workspace reproduces the
classification without touching product source:

| Policy | Result |
|---|---|
| current worker structure (`from_read & !Execute` on all read paths) | `PartiallyEnforced` |
| same rules, file-compatible rights for regular files | `FullyEnforced` |
| single `/etc/hosts` rule with `from_read & !Execute` | `PartiallyEnforced` |
| single `/etc/hosts` rule with file-compatible rights | `FullyEnforced` |
| no built-in read rules | `FullyEnforced` |
| directory paths only (`/proc/self`, `/usr/share/zoneinfo`) | `FullyEnforced` |

### 2.3 End-to-end impact

`adversarial/p3/imap-worker-landlock/engine-sync-failure.txt` records the real
managed engine:

```text
sync_once error: IMAP protocol error: isolated IMAP worker protocol failed: early eof
```

`IsolatedImapAccountEngine::sync_once` spawns the worker, the worker exits
during sandbox setup before writing a response, and the parent reports a
protocol failure. The same applies to `fetch_message_content` (the TUI's
`open_selected` path for header-only messages) and to the continuous sync
loop. On a host with Landlock ABI 6, the client's only managed receive path is
therefore unusable; the documented alternative is the explicitly unsandboxed
`Backend::managed_imap_account_engine_in_process` escape hatch, or no
synchronization at all.

The worker's own sandbox boundary is not weakened: `seccomp` and the
fail-closed policy still hold, and the archive worker's Landlock ruleset (no
path rules) still reports `FullyEnforced` with all four denial properties
(`adversarial/p3/imap-worker-landlock/archive-worker-control.txt`).

### 2.4 Reachability, severity and composition

- **Primary family:** `unclassified`. The fixed ontology reserves
  `denial_of_service` for attacker-triggerable consumption; this defect is
  triggered by host capability, and the boundary itself fails closed. It is a
  confirmed availability defect in a required security control, which is why
  it is not discarded.
- **Impact tier:** medium. Every ordinary Linux host with Landlock ABI 6 (and
  the common `/etc/hosts`-class files) cannot run the isolated receive path;
  the client either offers no synchronization or steers users to the
  unsandboxed in-process engine. No attacker input is required and there is no
  memory-safety or authority consequence.
- **Unintended behavior count:** 1. A directory-only access right is attached
  to regular-file rules, so the capability probe misclassifies a supported
  host as partially enforced.
- **Remediation component count:** 1. Choose the access set per path kind:
  file-compatible rights (`ReadFile`, optionally `WriteFile`) for regular
  files, `ReadDir`-capable rights for directories.

### 2.5 Remediation boundary and local verification

A disposable-copy patch that selects `AccessFs::from_file(abi) & !Execute &
!IoctlDev` for non-directory paths was verified before this report was
written (`adversarial/p3/imap-worker-landlock/corrected-policy-verification.txt`):

```text
{"profile_write_allowed":true,"credential_read_denied":true,
 "unrelated_profile_write_denied":true,"outside_read_denied":true,
 "outside_write_denied":true,"execute_denied":true,
 "udp_socket_denied":true,"unlisted_tcp_port_denied":true}
test worker_sandbox_is_fail_closed ... ok
```

All eight denial properties remain true and the guard test passes. The
reviewed checkout still contains the unmodified defect; the patch exists only
in the disposable copy used for verification.

---

## 3. P3-B — default worker discovery under the pinned cargo artifact layout

Retained case: `adversarial/p3/worker-discovery/results.txt`.

The repository pins `rust-toolchain.toml` channel `1.100.0`. With that
toolchain, integration test binaries are executed from
`target/<profile>/build/<package>-<hash>/out/`, not
`target/<profile>/deps/`. `worker_path::discover`
(`crates/mail-backend/src/worker_path.rs:14-44`) checks beside the executable,
then a `deps` parent, then the absolute `LIZARD_MAIL_LIBEXEC_DIR` fallback.
Under the observed layout none of those contain the archive worker, so
`Backend::default` archive inspection returns
`archive worker is unavailable: No such file or directory` and the security
evidence path degrades to `uninspectable_archive`. Passing the built worker
path explicitly returns `ArchiveInspection { state: Complete, ... }` with the
`documents/invoice.pdf.exe` entry that
`security_evidence::archive_security_reads_directory_metadata_but_never_inflates_entries`
expects, and that guard test fails at the reviewed commit.

The failure mode is safe: the missing worker becomes an uninspectable-archive
warning instead of a clean verdict, and production layouts (portable archive
places workers beside the main binary; Debian/RPM place them in
`/usr/libexec/lizard-mail`) are unaffected. The repository's own suite is red
for this case, and the inline comment ("Cargo integration tests run from
`target/{profile}/deps`") no longer describes the pinned toolchain.

---

## 4. Negative observations and remaining risk

- The full `lizard-mail-backend` suite at the reviewed commit ran with
  `--no-fail-fast`: library tests, archive, automation, backend, delivery
  authentication, IMAP headers/mutations, lifecycle, MIME API, organization,
  sending, spam, storage, threads and workflows suites pass; the two failures
  are the P3-A and P3-B guard tests above. Docker-requiring Dovecot suites are
  ignored and were not run.
- The complete `lizard-mail-tui` suite passes (21 library tests plus
  `app_smoke`, `fixture_smoke` and 10 isolation tests).
- A deletion/ownership matrix probe confirmed the documented semantics:
  removing a local folder deletes only messages with no remaining owner;
  messages shared with another account's local folder survive account removal;
  a body pin protects cached content from eviction but not the last copy from
  removal of its owning account/remote instance. No unintended deletion
  beyond the documented model was observed.
- Filter undo restores the captured local-folder snapshot and discards a
  membership added after the rule application. This is the explicitly
  documented behavior in `spec/mail-backend.md:426-430`; it is recorded here as
  an observation, not as a defect.
- Coverage limits: the reviewed checkout's GUI root package was not built; no
  remote system, real IP address or network endpoint was used; the corrected
  policy was verified only in a disposable copy; Landlock behavior was
  observed on one kernel (6.12.117). The P3-A mechanism is a crate-level
  compatibility rule, but different kernels or crate versions were not
  exercised.
