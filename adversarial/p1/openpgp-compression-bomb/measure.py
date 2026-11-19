#!/usr/bin/env python3
"""Measure one child so RUSAGE_CHILDREN does not include the Cargo build."""

import resource
import subprocess
import sys
import time

label, binary, profile, address_space = sys.argv[1:5]
if address_space == "none":
    command = [binary, "decrypt", profile]
else:
    command = [
        "bash",
        "-lc",
        f"ulimit -v {int(address_space)}; exec {binary} decrypt {profile}",
    ]
started = time.monotonic()
completed = subprocess.run(
    command,
    text=True,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    check=False,
)
print(f"[{label}]")
print(completed.stdout, end="")
print(f"exit_status={completed.returncode}")
print(f"wall_ms={(time.monotonic() - started) * 1000:.1f}")
print(f"max_rss_kib={resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss}")

