#!/usr/bin/env python3
"""Turn a copied checkout into the minimal workspace used for CLI releases."""

from __future__ import annotations

import argparse
from pathlib import Path


CLI_WORKSPACE = """\
[workspace]
members = [
    "crates/mail-backend",
    "crates/mail-tui",
    "crates/verified-kernel",
    "vendor/async-imap",
    "vendor/mail-auth",
]
resolver = "2"

[profile.release]
debug = 1
panic = "abort"
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    manifest = args.root.resolve() / "Cargo.toml"
    original = manifest.read_text(encoding="utf-8")
    if 'name = "lizard"' not in original or "[patch.crates-io]" not in original:
        raise SystemExit(f"refusing to replace unexpected root manifest: {manifest}")
    manifest.write_text(CLI_WORKSPACE, encoding="utf-8")


if __name__ == "__main__":
    main()
