# P3·A — isolated IMAP worker Landlock misclassification

`run.py` reproduces the Pass-3 finding that the isolated IMAP synchronization
worker refuses to start on a Landlock-capable Linux host because its own
ruleset is reported as `PartiallyEnforced`.

Run from the repository root:

```sh
python3 adversarial/p3/imap-worker-landlock/run.py
```

The driver never modifies the reviewed checkout. It copies the tree to a
disposable temporary directory, applies the same CLI release workspace
transformation as `packaging/reproducible-build.sh`, builds
`lizard-mail-sync-worker`, and then records:

1. `lizard-mail-sync-worker --sandbox-self-test` output (exits 1 with
   `ruleset: PartiallyEnforced`);
2. `cargo test -p lizard-mail-backend --test imap_worker
   worker_sandbox_is_fail_closed -- --exact` output (fails at
   `crates/mail-backend/tests/imap_worker.rs:83`);
3. a standalone Landlock bisection copied from `bisection.rs` into the
   disposable workspace's `crates/mail-backend/examples/` directory. The
   `current` mode mirrors `enter_landlock`; the `corrected` mode selects
   file-compatible access rights for regular files and reports
   `FullyEnforced`.

Retained results:

| Path | Contents |
|---|---|
| `results.txt` | Driver output at the reviewed commit on kernel 6.12.117 |
| `engine-sync-failure.txt` | `IsolatedImapAccountEngine::sync_once` ends in `early eof` because the worker dies during sandbox setup |
| `corrected-policy-verification.txt` | Disposable-copy check that file-compatible rights restore `FullyEnforced`, keep all eight self-test denials, and pass the guard test |

Environment overrides for reuse: `P3_WORKSPACE`, `CARGO_TARGET_DIR`,
`P3_RESULTS`. The retained `results.txt` was produced with
`P3_WORKSPACE=/home/user/p3-build/repo` (an external disposable copy used for
this review) and `CARGO_TARGET_DIR=/home/user/p3-build/repo/target`; a fresh
run without overrides creates its own copy and target directory.

The driver exits 0 when the defect reproduces, 2 when the host does not
reproduce it, and 1 on harness failure.
