#!/usr/bin/env python3
"""Verify rendering source against pinned Firefox bytes and reviewed patches."""

import hashlib
import json
import pathlib
import sys


ROOT = pathlib.Path(__file__).resolve().parents[1]
VENDOR = ROOT / "vendor/wr"
meta = json.loads((ROOT / "spec/webrender-source.json").read_text())
patch_meta = json.loads((ROOT / "spec/webrender-local-patches.json").read_text())
patches = {entry["path"]: entry for entry in patch_meta["entries"]}
upstream_paths = {entry["path"] for entry in meta["entries"]}
bad = []
applied = []

if patch_meta["upstream_revision"] != meta["git_revision"]:
    bad.append(("local patch manifest", "upstream revision mismatch"))
if len(patches) != len(patch_meta["entries"]):
    bad.append(("local patch manifest", "duplicate path"))

for path in patches.keys() - upstream_paths:
    bad.append((path, "local patch does not name an upstream file"))

for entry in meta["entries"]:
    if entry["path"] == "Cargo.toml":
        continue  # workspace membership intentionally reduced
    path = VENDOR / entry["path"]
    if not path.is_file():
        bad.append((entry["path"], "missing"))
        continue
    data = path.read_bytes()
    actual_blob = hashlib.sha1(
        b"blob " + str(len(data)).encode() + b"\0" + data
    ).hexdigest()
    patch = patches.get(entry["path"])
    if actual_blob == entry["sha"]:
        if patch is not None:
            bad.append((entry["path"], "stale local patch entry"))
        continue
    if patch is None:
        bad.append((entry["path"], "modified without a reviewed local patch"))
        continue
    actual_sha256 = hashlib.sha256(data).hexdigest()
    if actual_sha256 != patch["sha256"]:
        bad.append((entry["path"], "local patch hash mismatch"))
        continue
    applied.append({"path": entry["path"], "rationale": patch["rationale"]})

adapters = json.loads((ROOT / "spec/standalone-adapters.json").read_text())
allowed = upstream_paths | {"fog/Cargo.toml", "fog/src/main.rs"}
for path in VENDOR.rglob("*"):
    relative = str(path.relative_to(VENDOR))
    if path.is_file() and relative not in allowed:
        bad.append((relative, "unexpected source"))
for entry in adapters["files"]:
    actual = hashlib.sha256((ROOT / entry["path"]).read_bytes()).hexdigest()
    if actual != entry["sha256"]:
        bad.append((entry["path"], "standalone adapter modified"))

print(
    json.dumps(
        {
            "revision": meta["git_revision"],
            "checked": len(meta["entries"]) - 1,
            "local_patches": applied,
            "differences": bad,
        },
        indent=2,
    )
)
sys.exit(bool(bad))
