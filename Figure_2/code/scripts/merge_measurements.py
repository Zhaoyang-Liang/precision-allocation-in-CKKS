#!/usr/bin/env python3
"""Merge verified compact exports and build user-facing comparison tables."""
import argparse
import csv
import hashlib
import json
from pathlib import Path


def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read(path):
    if not path.exists():return []
    with path.open() as f:return list(csv.DictReader(f))


def write(path,rows):
    if not rows:return
    fields=list(dict.fromkeys(k for r in rows for k in r))
    with path.open('x',newline='',encoding='utf-8-sig' if path.name=='overview.csv' else 'utf-8') as f:
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows(rows)


def result_order(row):
    return ({'small':0,'capacity':1,'boundary':2}.get(row['scene'],3),
            int(row['target_bits']),int(row['depth']),
            {'grow':0,'reciprocal':1}.get(row['input_family'],2),
            int(row['messages']),int(row['classes']),
            0 if 'min_N_then_Q' in row.get('priorities',row.get('priority','')) else 1,
            row['candidate_id'],int(row.get('repeat',row.get('construction_repeat',0))))


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--export',action='append',required=True)
    ap.add_argument('--expected-tasks',action='append',default=[])
    ap.add_argument('--out',required=True)
    ap.add_argument('--allow-pilot',action='store_true')
    args=ap.parse_args()
    out=Path(args.out);out.mkdir(parents=True,exist_ok=False)
    names=('runs.csv','summary.csv','configurations.csv','unit_preparation.csv','remote_raw_manifest.csv')
    data={n:[] for n in names};provenance=[]
    for name in args.export:
        p=Path(name).resolve();manifest=json.loads((p/'manifest.json').read_text())
        if not manifest['all_selected_measurements_complete'] or manifest['missing_or_failed_runs']:
            raise ValueError('Only complete audited exports can enter the final measured comparison')
        for file,h in manifest['files'].items():
            if sha(p/file)!=h:raise ValueError('Export CSV hash mismatch')
        provenance.append({'directory':str(p),'manifest_sha256':sha(p/'manifest.json')})
        for file in names:data[file].extend(read(p/file))
    for file,key in (('runs.csv',lambda r:(r['task_id'],r['candidate_id'],r['repeat'])),
                     ('summary.csv',lambda r:(r['task_id'],r['candidate_id'])),
                     ('configurations.csv',lambda r:(r['task_id'],r['candidate_id'])),
                     ('remote_raw_manifest.csv',lambda r:r['path'])):
        keys=[key(r) for r in data[file]]
        if len(set(keys))!=len(keys):raise ValueError('Duplicate records in '+file)
    for file in ('runs.csv','summary.csv','configurations.csv','unit_preparation.csv'):
        data[file].sort(key=result_order)
    data['remote_raw_manifest.csv'].sort(key=lambda r:r['path'])
    runs=data['runs.csv'];summaries=data['summary.csv']
    if any(r['pilot_only']!='False' for r in summaries) and not args.allow_pilot:
        raise ValueError('Pilot results cannot enter formal comparison')
    if any(int(r['repeat_count'])!=5 or r['all_five_runs_pass']!='True' for r in summaries):
        raise ValueError('A full five-repeat group is required')
    if len(runs)!=5*len(summaries):raise ValueError('Run/summary coverage mismatch')
    expected={t['id'] for filename in args.expected_tasks for t in json.loads(Path(filename).read_text())['tasks']}
    observed={r['task_id'] for r in summaries}
    if expected and expected!=observed:
        raise ValueError('Task coverage mismatch: missing='+str(sorted(expected-observed))+' extra='+str(sorted(observed-expected)))
    comparisons=[]
    priorities=('min_N_then_Q','online_word_proxy')
    for task_id in sorted(observed):
        for priority in priorities:
            group=[r for r in summaries if r['task_id']==task_id and priority in r['priorities'].split('|')]
            # Older pipeline pilots predate explicit selection priorities.
            if args.allow_pilot and not group:continue
            if len(group)!=3 or {r['classes'] for r in group}!={'1','2','4'}:
                raise ValueError('Missing/duplicate method for registered task and priority')
            base=next(r for r in group if r['classes']=='1')
            best=min(float(r['median_online_ms']) for r in group)
            for r in group:
                if float(r['worst_actual_precision_bits'])<int(r['target_bits']):
                    raise ValueError('Business accuracy failed')
                comparisons.append({k:r[k] for k in ('task_id','scene','messages','target_bits','depth','input_family','classes','candidate_id','theta','N','Q_bits','Q_count','batches','median_online_ms','min_online_ms','max_online_ms','worst_actual_precision_bits')}|
                    {'priority':priority,'ordinary_candidate_id':base['candidate_id'],
                     'Q_bit_reduction':1-int(r['Q_bits'])/int(base['Q_bits']),
                     'N_reduction_factor':int(base['N'])/int(r['N']),
                     'median_speedup_vs_ordinary':float(base['median_online_ms'])/float(r['median_online_ms']),
                     'smallest_observed_median_among_three_preselected_methods':float(r['median_online_ms'])==best})
    comparisons.sort(key=result_order)
    overview=[]
    for r in summaries:
        overview.append({'scene':{'small':'small','capacity':'capacity','boundary':'boundary'}.get(r['scene'],r['scene']),
            'input_range':'[1,2]' if r['input_family']=='grow' else '[1/2,1]','messages':r['messages'],
            'target_bits':r['target_bits'],'depth':r['depth'],
            'method':{'1':'CKKS','2':'two_classes','4':'four_classes'}[r['classes']],
            'selection_rule':';'.join({'min_N_then_Q':'min_N_then_Q',
                                  'online_word_proxy':'online_word_proxy'}.get(x,x)
                                 for x in r['priorities'].split('|')),
            'theta':r['theta'],'N':r['N'],'Q_bits':r['Q_bits'],
            'Q_count':r['Q_count'],'batches':r['batches'],'worst_precision_bits':r['worst_actual_precision_bits'],
            'median_online_ms':r['median_online_ms'],'min_online_ms':r['min_online_ms'],'max_online_ms':r['max_online_ms'],
            'candidate_id':r['candidate_id']})
    for file,rows in data.items():write(out/file,rows)
    write(out/'comparisons.csv',comparisons);write(out/'overview.csv',overview)
    manifest={'schema':'pa07-final-compact-data-v1','pilot_allowed':args.allow_pilot,'tasks':len(observed),
        'configurations':len(summaries),'audited_runs':len(runs),'source_exports':provenance,
        'expected_task_files':[{'path':str(Path(p).resolve()),'sha256':sha(p)} for p in args.expected_tasks],
        'raw_data_location':'/home/u9920250039/projects/pa-fixed-precision-20261013',
        'script_sha256':sha(__file__),'files':{p.name:sha(p) for p in out.glob('*.csv')},
        'interpretation':'Finite preselected parameter families; speedup is a ratio of five-repeat observed medians, not a global optimum or confidence guarantee.'}
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(len(observed),'tasks;',len(summaries),'configurations;',len(runs),'audited runs')


if __name__=='__main__':main()
