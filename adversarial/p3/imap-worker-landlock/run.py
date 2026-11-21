#!/usr/bin/env python3
"""Reproduce the isolated IMAP worker's Landlock misclassification (Pass 3).

The driver never modifies the reviewed checkout. By default it builds a
disposable CLI workspace copy (the same transformation used by
``packaging/reproducible-build.sh``) and then:

1. builds the production worker binaries;
2. runs ``lizard-mail-sync-worker --sandbox-self-test``;
3. runs the retained guard test
   ``cargo test -p lizard-mail-backend --test imap_worker worker_sandbox_is_fail_closed``;
4. runs a standalone Landlock bisection that mirrors ``enter_landlock`` with
   the current file-path access set and with file-compatible access rights.

Environment overrides:

- ``P3_WORKSPACE``: reuse an existing prepared workspace instead of creating a
  disposable copy (useful when the same tree was already built).
- ``CARGO_TARGET_DIR``: choose the build target directory. The default is
  ``<repository>/target/p3-imap-worker-landlock`` so the (gitignored) build
  tree lives on the repository's filesystem rather than a small temporary one.
- ``P3_RESULTS``: path for retained output. Defaults to ``results.txt`` beside
  this file.

The script exits 0 when the defect reproduces, 2 when the environment does not
reproduce it (for example a kernel without the full Landlock ABI), and 1 on
harness failure.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def run(command: list[str], cwd: Path, env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=str(cwd), env=env, text=True, capture_output=True)
    return result


def prepare_workspace(env: dict[str, str], target_dir: Path) -> Path:
    reused = os.environ.get("P3_WORKSPACE")
    if reused:
        workspace = Path(reused).resolve()
        print(f"[harness] reusing workspace {workspace}")
    else:
        scratch = Path(tempfile.mkdtemp(prefix="p3-imap-worker-"))
        workspace = scratch / "workspace"
        print(f"[harness] copying checkout to {workspace}")
        shutil.copytree(
            ROOT,
            workspace,
            ignore=shutil.ignore_patterns(".git", "target", "release"),
            symlinks=True,
        )
    workspace = workspace.resolve()
    manifest = (workspace / "Cargo.toml").read_text(encoding="utf-8")
    if 'name = "lizard"' in manifest or "[patch.crates-io]" in manifest:
        prepared = run(
            [sys.executable, "packaging/prepare-cli-workspace.py", str(workspace)],
            workspace,
            env,
        )
        if prepared.returncode:
            print(prepared.stdout)
            print(prepared.stderr, file=sys.stderr)
            raise SystemExit(1)
    else:
        print("[harness] workspace manifest is already the CLI release workspace")
    shutil.copyfile(workspace / "packaging/Cargo.cli.lock", workspace / "Cargo.lock")
    target_dir.mkdir(parents=True, exist_ok=True)
    examples = workspace / "crates/mail-backend/examples"
    examples.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(HERE / "bisection.rs", examples / "p3_landlock_bisection.rs")
    env["CARGO_TARGET_DIR"] = str(target_dir)
    return workspace


def main() -> int:
    target_override = os.environ.get("CARGO_TARGET_DIR")
    scratch = Path(tempfile.mkdtemp(prefix="p3-imap-worker-scratch-"))
    target_dir = (
        Path(target_override).resolve()
        if target_override
        else ROOT / "target" / "p3-imap-worker-landlock"
    )
    target_dir.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env.setdefault("LC_ALL", "C")
    env["CARGO_TERM_COLOR"] = "never"

    lines: list[str] = []

    def record(text: str) -> None:
        print(text)
        lines.append(text)

    record(f"uname: {platform.uname().release}")
    record(f"python: {platform.python_version()}")

    workspace = prepare_workspace(env, target_dir)
    record(f"workspace: {workspace}")
    record(f"CARGO_TARGET_DIR: {env['CARGO_TARGET_DIR']}")

    build = run(
        ["cargo", "build", "--locked", "-q", "-p", "lizard-mail-backend", "--bins"],
        workspace,
        env,
    )
    record(f"cargo build --bins exit: {build.returncode}")
    if build.returncode:
        record(build.stderr[-2000:])
        return 1

    worker = target_dir / "debug" / "lizard-mail-sync-worker"
    self_test_profile = scratch / "self-test-profile"
    self_test = run(
        [str(worker), "--sandbox-self-test", str(self_test_profile)],
        workspace,
        env,
    )
    record(f"worker --sandbox-self-test exit: {self_test.returncode}")
    record((self_test.stdout + self_test.stderr).strip())

    guard = run(
        [
            "cargo",
            "test",
            "--locked",
            "-p",
            "lizard-mail-backend",
            "--test",
            "imap_worker",
            "worker_sandbox_is_fail_closed",
            "--",
            "--exact",
        ],
        workspace,
        env,
    )
    record(f"guard test exit: {guard.returncode}")
    tail = (guard.stdout + guard.stderr).strip().splitlines()
    record("\n".join(tail[-14:]))

    for mode in ("current", "corrected"):
        probe = run(
            [
                "cargo",
                "run",
                "--locked",
                "-q",
                "-p",
                "lizard-mail-backend",
                "--example",
                "p3_landlock_bisection",
                "--",
                mode,
            ],
            workspace,
            env,
        )
        record(f"bisection[{mode}] exit: {probe.returncode}")
        record((probe.stdout + probe.stderr).strip())

    results_path = Path(os.environ.get("P3_RESULTS", HERE / "results.txt"))
    results_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[harness] results written to {results_path}")

    reproduced = self_test.returncode != 0 and "PartiallyEnforced" in self_test.stderr
    if reproduced and guard.returncode != 0:
        print("[harness] defect reproduced: worker self-test and guard test fail")
        return 0
    print("[harness] defect did not reproduce in this environment")
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError as error:
        print(f"[harness] missing tool: {error}", file=sys.stderr)
        raise SystemExit(1)
