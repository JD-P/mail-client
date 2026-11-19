#!/usr/bin/env python3
"""Run the retained LIST flood in a fresh process and report peak RSS."""

import os
import resource
import subprocess
import sys


def main() -> int:
    count = int(sys.argv[1]) if len(sys.argv) > 1 else 20_000
    limit_kib = int(sys.argv[2]) if len(sys.argv) > 2 else None
    manifest = os.path.join(os.path.dirname(__file__), "Cargo.toml")
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
    environment = os.environ.copy()
    environment["CARGO_TARGET_DIR"] = os.path.join(root, "target")
    build = [
        "cargo",
        "build",
        "-q",
        "--release",
        "--locked",
        "--manifest-path",
        manifest,
    ]
    built = subprocess.run(build, env=environment)
    if built.returncode:
        return built.returncode
    command = [
        os.path.join(root, "target", "release", "p2-imap-response-flood"),
        "list-flood",
        str(count),
    ]
    set_limit = None
    if limit_kib is not None:
        def set_limit():
            ceiling = limit_kib * 1024
            resource.setrlimit(resource.RLIMIT_AS, (ceiling, ceiling))
    before = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    completed = subprocess.run(
        command,
        text=True,
        capture_output=True,
        env=environment,
        preexec_fn=set_limit,
    )
    after = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    sys.stdout.write(completed.stdout)
    sys.stderr.write(completed.stderr)
    print(
        f"exit={completed.returncode} external_peak_rss_kib={max(before, after)} "
        f"address_space_limit_kib={limit_kib or 'none'}"
    )
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
