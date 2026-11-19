#!/usr/bin/env python3
"""Build and measure the P1-A control, candidate, and bounded-process crash."""

from pathlib import Path
import os
import subprocess
import sys
import tempfile
import time

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
TARGET = REPO / "target"
MANIFEST = HERE / "Cargo.toml"
BIN = TARGET / "debug" / "p1-openpgp-compression-bomb"


def run(command, *, env=None):
    started = time.monotonic()
    completed = subprocess.run(
        command,
        cwd=REPO,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return completed, (time.monotonic() - started) * 1000


def decrypt(label, profile, *, address_space_kib=None):
    completed, _ = run(
        [
            sys.executable,
            str(HERE / "measure.py"),
            label,
            str(BIN),
            profile,
            "none" if address_space_kib is None else str(address_space_kib),
        ]
    )
    print(completed.stdout, end="")


def main():
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = str(TARGET)
    completed, _ = run(
        ["cargo", "build", "--locked", "--manifest-path", str(MANIFEST)],
        env=environment,
    )
    if completed.returncode:
        raise SystemExit(completed.stdout)

    with tempfile.TemporaryDirectory(prefix="lizard-p1-control-") as control:
        generated, _ = run([str(BIN), "generate", control, "1"])
        print("[control fixture]")
        print(generated.stdout, end="")
        decrypt("control decrypt", control)

    with tempfile.TemporaryDirectory(prefix="lizard-p1-candidate-") as candidate:
        generated, _ = run([str(BIN), "generate", candidate, "128"])
        print("[candidate fixture]")
        print(generated.stdout, end="")
        decrypt("candidate decrypt", candidate)
        decrypt("candidate under 180000 KiB RLIMIT_AS", candidate, address_space_kib=180000)


if __name__ == "__main__":
    main()

