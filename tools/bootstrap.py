#!/usr/bin/env python3
"""Fetch the exact checksummed Linux x86-64 oracle/verifier releases."""
import argparse,hashlib,json,pathlib,shutil,stat,tarfile,urllib.request,zipfile
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--dest',type=pathlib.Path,default=ROOT/'.tools');p.add_argument('--cache',type=pathlib.Path);p.add_argument('--only',choices=['firefox','geckodriver','verus']);a=p.parse_args()
a.dest.mkdir(parents=True,exist_ok=True);cache=a.cache or a.dest/'cache';cache.mkdir(parents=True,exist_ok=True)
for tool in json.loads((ROOT/'spec/toolchains.json').read_text())['tools']:
    if a.only and tool['name']!=a.only:continue
    source=cache/tool['file']
    if not source.exists():
        partial=source.with_suffix(source.suffix+'.partial')
        with urllib.request.urlopen(tool['url'],timeout=60) as response,partial.open('wb') as out:
            shutil.copyfileobj(response,out)
        partial.replace(source)
    if source.stat().st_size!=tool['bytes'] or hashlib.sha256(source.read_bytes()).hexdigest()!=tool['sha256']:
        raise SystemExit('Checksum mismatch: '+str(source))
    if source.suffix=='.zip':
        with zipfile.ZipFile(source) as z:
            for entry in z.infolist():
                path=pathlib.PurePosixPath(entry.filename)
                mode=entry.external_attr>>16
                if path.is_absolute() or '..' in path.parts or stat.S_ISLNK(mode):raise SystemExit('Unsafe archive path')
                dest=a.dest/path
                if entry.is_dir():dest.mkdir(parents=True,exist_ok=True);continue
                dest.parent.mkdir(parents=True,exist_ok=True)
                with z.open(entry) as src,dest.open('wb') as out:shutil.copyfileobj(src,out)
                dest.chmod(0o755 if mode&0o111 else 0o644)
    else:
        with tarfile.open(source) as tar:tar.extractall(a.dest,filter='data')
    print(tool['name'],tool['sha256'])
