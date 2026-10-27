"""Prepare real-estimator inputs from NEW public backend plans; run no attacks.

Only parameters and provenance are exported. No estimated security value is
inserted, and no formal HE configuration is authorized by this file.
"""
import argparse
import hashlib
import json
from pathlib import Path

from estimate_cases import plan_cases


def make_union(plans):
    sources=[];cases={}
    for path in plans:
        path=Path(path).resolve();raw=path.read_bytes();plan=json.loads(raw)
        checked=plan_cases(plan)
        sources.append({'path':str(path),'sha256':hashlib.sha256(raw).hexdigest()})
        for branch,case in zip(plan['branches'],checked):
            key=(case['N'],tuple(case['Q']),tuple(case['P']))
            if key not in cases:
                cases[key]={'id':'case_'+str(len(cases)+1).zfill(3),'parameters':branch['parameters'],
                            'q_est_log2':case['q_est_log2'],'sources':[]}
            cases[key]['sources'].append({'plan':str(path),'branch':branch['id']})
    rows=list(cases.values())
    return {'schema':'new-security-union-plan-v1','source_plans':sources,'branches':rows,
            'HE_executions':0,'attacks_executed':0,'security_estimated':False,
            'distinct_estimator_inputs':len({(r['parameters']['n'],r['q_est_log2']) for r in rows}),
            'scope':'pending inputs only; full N and ceil(log2(maximum relevant QP)); no safety conclusion'}


if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('--out',required=True);a.add_argument('directories',nargs='+');v=a.parse_args()
    plans=[]
    for folder in v.directories:
        directory=Path(folder);audit=json.loads((directory/'backend_crosscheck.json').read_text())
        if not audit['all_pass']:raise ValueError('backend cross-check must pass before security queue')
        for row in audit['records']:
            config=directory/row['config']
            plans.append(config.with_name(config.stem+'_plan.json'))
    union=make_union(plans)
    with Path(v.out).open('x',encoding='utf-8') as output:json.dump(union,output,ensure_ascii=False,indent=2);output.write('\n')
    print('public plans',len(plans),'exact parameter cases',len(union['branches']),
          'distinct real-estimator inputs',union['distinct_estimator_inputs'],'attacks executed 0')
