#!/usr/bin/env python3
"""One-shot CLI latency and maximum-process RSS; not an older-hardware emulator."""
import argparse,json,os,pathlib,statistics,subprocess,tempfile,time
ROOT=pathlib.Path(__file__).resolve().parents[1]
p=argparse.ArgumentParser();p.add_argument('--binary',required=True);p.add_argument('--iterations',type=int,default=5);p.add_argument('--one-cpu',action='store_true');p.add_argument('--output',default='results/benchmark.json');a=p.parse_args()
if a.iterations<1 or a.iterations>100:raise SystemExit('iterations must be 1..100')
if a.one_cpu:os.sched_setaffinity(0,{min(os.sched_getaffinity(0))})
rows=[]
with tempfile.TemporaryDirectory(prefix='lizard-bench-') as tmp:
    tmp=pathlib.Path(tmp);long=tmp/'long.html';long.write_text('<!doctype html><meta charset=utf-8><style>body{font:16px/24px sans-serif}p{margin:0}</style>'+''.join('<p>Message paragraph '+str(i)+': ordinary email text with a few words.</p>'for i in range(300)))
    for name,path in [('text',ROOT/'tests/fixtures/text-basic.html'),('nested-table',ROOT/'tests/fixtures/nested-email-table.html'),('long-text',long)]:
        samples=[]
        for i in range(a.iterations):
            start=time.perf_counter();proc=subprocess.Popen([str(pathlib.Path(a.binary).resolve()),'render',str(path),str(tmp/'frame.png'),'800','600'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
            pid,status,usage=os.wait4(proc.pid,0);proc.returncode=os.waitstatus_to_exitcode(status)
            stdout,stderr=proc.communicate();elapsed=(time.perf_counter()-start)*1000
            if proc.returncode:raise SystemExit(stderr.decode(errors='replace'))
            samples.append({'wall_ms':elapsed,'maximum_process_rss_kib':usage.ru_maxrss,'renderer':json.loads(stdout)})
        rows.append({'case':name,'median_wall_ms':statistics.median(x['wall_ms']for x in samples),'maximum_process_rss_kib':max(x['maximum_process_rss_kib']for x in samples),'samples':samples})
out=ROOT/a.output;out.parent.mkdir(exist_ok=True,parents=True);result={'cpu_affinity':sorted(os.sched_getaffinity(0)),'viewport':[800,600],'mode':'sandboxed fresh worker per render, no diagnostic trace; includes font/renderer startup, layout, paint, IPC and PNG encoding','memory_method':'Maximum-process RSS from kernel wait4 accounting, including reaped descendants. This is the maximum for a process, not the aggregate concurrent memory of the host and worker. /proc process-tree sampling was unavailable in this environment.','limitations':'Cloud CPU, no old-machine simulation. Warm filesystem cache. Retained Painter frame latency is not measured here.','results':rows};out.write_text(json.dumps(result,indent=2)+'\n');print(json.dumps({'results':[{k:v for k,v in r.items()if k!='samples'}for r in rows]}))
