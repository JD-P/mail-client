#!/usr/bin/env python3
"""Require one version for every executable shipped as Lizard Mail."""

from __future__ import annotations

import argparse
import os
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PRODUCT_MANIFESTS = (
    ROOT / "Cargo.toml",
    ROOT / "crates/mail-backend/Cargo.toml",
    ROOT / "crates/mail-tui/Cargo.toml",
    ROOT / "crates/verified-kernel/Cargo.toml",
)


def package_version(path: Path) -> tuple[str, str]:
    with path.open("rb") as handle:
        package = tomllib.load(handle)["package"]
    return str(package["name"]), str(package["version"])


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--print-version", action="store_true")
    args = parser.parse_args()

    packages = [package_version(path) for path in PRODUCT_MANIFESTS]
    versions = {version for _, version in packages}
    if len(versions) != 1:
        print("release packages do not share one version:", file=sys.stderr)
        for (name, version), path in zip(packages, PRODUCT_MANIFESTS, strict=True):
            print(f"  {path.relative_to(ROOT)}: {name} {version}", file=sys.stderr)
        return 1
    version = versions.pop()

    if os.environ.get("GITHUB_REF_TYPE") == "tag":
        tag = os.environ.get("GITHUB_REF_NAME", "")
        if tag != f"v{version}":
            print(
                f"release tag {tag!r} does not match package version v{version}",
                file=sys.stderr,
            )
            return 1

    if args.print_version:
        print(version)
    else:
        print(f"release version consistency: {version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
