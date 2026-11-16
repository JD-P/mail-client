#!/usr/bin/env python3
"""Verify rendering source bytes against the pinned Firefox release Git tree."""
import hashlib,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[1];meta=json.loads((ROOT/'spec/webrender-source.json').read_text());bad=[]
for entry in meta['entries']:
    if entry['path']=='Cargo.toml':continue  # workspace membership intentionally reduced
    p=ROOT/'vendor/wr'/entry['path']
    if not p.is_file():bad.append((entry['path'],'missing'));continue
    data=p.read_bytes();actual=hashlib.sha1(b'blob '+str(len(data)).encode()+b'\0'+data).hexdigest()
    if actual!=entry['sha']:bad.append((entry['path'],'modified'))
adapters=json.loads((ROOT/'spec/standalone-adapters.json').read_text())
allowed={e['path'] for e in meta['entries']}|{'fog/Cargo.toml','fog/src/main.rs'}
for path in (ROOT/'vendor/wr').rglob('*'):
    if path.is_file() and str(path.relative_to(ROOT/'vendor/wr')) not in allowed:bad.append((str(path),'unexpected source'))
for entry in adapters['files']:
    if hashlib.sha256((ROOT/entry['path']).read_bytes()).hexdigest()!=entry['sha256']:bad.append((entry['path'],'standalone adapter modified'))
print(json.dumps({'revision' :meta['git_revision'],'checked':len(meta['entries'])-1,'differences':bad},indent=2))
sys.exit(bool(bad))
