#!/usr/bin/env python3
"""Portable source/results checkpoint, excluding binaries and toolchain caches."""
import argparse,hashlib,json,pathlib,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('output');args=p.parse_args();out=pathlib.Path(args.output).resolve();out.parent.mkdir(parents=True,exist_ok=True)
files=[]
for path in ROOT.rglob('*'):
    if not path.is_file() or path==out:continue
    parts=path.relative_to(ROOT).parts
    if any(x in parts for x in ['target','.git','.tools','__pycache__']):continue
    if path.suffix in ['.rlib','.rmeta','.o','.so']:continue
    files.append(path)
with zipfile.ZipFile(out,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    manifest=[]
    for path in sorted(files):
        relative=str(path.relative_to(ROOT));z.write(path,'lizard/'+relative)
        manifest.append({'path':relative,'bytes':path.stat().st_size,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
    z.writestr('lizard/ARTIFACT-MANIFEST.json',json.dumps(manifest,indent=2)+'\n')
with zipfile.ZipFile(out) as z:assert z.testzip() is None
print(json.dumps({'path':str(out),'bytes':out.stat().st_size,'files':len(files),'sha256':hashlib.sha256(out.read_bytes()).hexdigest()}))
