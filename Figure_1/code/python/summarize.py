"""Summarize saved, audited runs. No synthetic or fitted HE observations."""
import argparse
import csv
import hashlib
import json
import re
from collections import defaultdict
from pathlib import Path

NAME = re.compile(r'r([24])-(grow|shrink)-t(\d+)-rep(\d+)$')

def collect(root):
    runs, layers, pending = [], [], []
    settings_hashes=set()
    for path in sorted(root.glob('r*-*-t*-rep*/result.json')):
        name=path.parent.name
        match=NAME.fullmatch(name)
        if not match: continue
        audit=root/(name+'.audit.json')
        if not audit.exists():pending.append(name);continue
        a=json.loads(audit.read_text());d=json.loads(path.read_text())
        assert a['pass'] and a['run_manifest_sha256']==hashlib.sha256((path.parent/'manifest.json').read_bytes()).hexdigest(), name
        r,family,t,rep=match.groups();r,t,rep=map(int,(r,t,rep))
        assert (d['classes'],d['input_family'],d['requested_theta'])==(r,family,t),name
        assert d['status']=='completed' and d['chain_depth_limit']==7,name
        settings_hashes.add(d['settings_sha256'])
        last=d['last_recoverable_depth'];first=d['first_failure_depth']
        terminal=d['terminal_reason']
        assert (terminal=='restoration_wrap' and first==last+1) or (terminal=='chain_exhausted' and last==7 and first==-1),name
        row=dict(run=name,classes=r,input_family=family,theta=t,replicate=rep,
                 nominal_useful_gain=(r-1)*t,last_recoverable_depth=last,
                 first_failure_depth=first,terminal_reason=terminal,
                 last_valid_precision_bits=d['layers'][last]['useful_precision_bits'] if last>=0 else '',
                 first_failure_precision_bits=d['layers'][first]['useful_precision_bits'] if first>=0 else '',
                 key_family_sha256=d['key_family_sha256'],host=d['host'],
                 slurm_job_id=d['slurm_job_id'],slurm_array_task_id=d['slurm_array_task_id'],
                 actual_log2_useful_unit_weight=d['actual_log2_unit_weights'][0],
                 diagnostic_wall_seconds=d['diagnostic_wall_seconds'])
        runs.append(row)
        for l in d['layers']:
            layers.append(dict(run=name,classes=r,input_family=family,theta=t,replicate=rep,
                depth=l['depth'],wrap=l['wrap'],useful_precision_bits=l['useful_precision_bits'],
                Q_bits=l['Q_bits'],remaining_Q_primes=l['remaining_Q_primes'],scale_log2=l['scale_log2'],
                shadow_to_halfQ_log2=l['shadow_to_halfQ_log2'],max_reference_log2=l['max_reference_log2'],
                worst_message=l['worst_message'],worst_slot=l['worst_slot']))
    assert len(settings_hashes)<=1,'mixed formal settings'
    return runs,layers,pending

def write_csv(path, rows):
    if not rows: return
    temporary=path.with_suffix(path.suffix+'.tmp')
    with temporary.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    temporary.replace(path)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--results',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);ap.add_argument('--require-manifests',type=Path,nargs='*');args=ap.parse_args()
    runs,layers,pending=collect(args.results);args.output.mkdir(parents=True,exist_ok=True)
    if args.require_manifests:
        expected={line.split()[-1] for p in args.require_manifests for line in p.read_text().splitlines() if line.strip()}
        actual={r['run'] for r in runs};assert expected==actual,{'missing':sorted(expected-actual),'unexpected':sorted(actual-expected)}
    runs.sort(key=lambda x:(x['classes'],x['input_family'],x['theta'],x['replicate']))
    write_csv(args.output/'runs.csv',runs);write_csv(args.output/'layers.csv',layers)
    counts=defaultdict(int)
    for row in runs:counts[f"r{row['classes']}-{row['input_family']}-{row['terminal_reason']}"]+=1
    summary={'audited_runs':len(runs),'saved_layers':len(layers),'pending_audit':pending,'counts':dict(counts),'independent_key_families':len({x['key_family_sha256'] for x in runs})}
    summary['coarse_runs']=sum(x['replicate']<=3 and x['theta']%10==0 for x in runs)
    summary['refinement_runs']=sum(x['replicate']<=3 and x['theta']%10!=0 for x in runs)
    summary['additional_repeats']=sum(x['replicate']>=4 for x in runs)
    temporary=args.output/'summary.json.tmp'
    temporary.write_text(json.dumps(summary,indent=2)+'\n');temporary.replace(args.output/'summary.json')
    print(json.dumps(summary))

if __name__=='__main__':main()
