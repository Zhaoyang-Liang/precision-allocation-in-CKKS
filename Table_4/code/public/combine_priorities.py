"""Combine preregistered dummy-budget alternatives before HE selection.

Reuse public configurations and certificates by absolute reference. Do not copy
or edit them. Their actual multipliers stay in each candidate; a dummy budget
is not a requirement on an extra business output.
"""
import argparse
from copy import deepcopy
import hashlib
import json
from pathlib import Path


def combine(sources):
    rows=[];checks=[];question=None;budgets=set();provenance=[];seen={}
    for filename in sources:
        path=Path(filename).resolve();raw=path.read_bytes();data=json.loads(raw)
        audit_path=path.parent/'backend_crosscheck.json';audit=json.loads(audit_path.read_text())
        if data['schema']!='new-stage-public-priorities-v1' or not audit['all_pass']:
            raise ValueError('only backend-checked public priorities may be combined')
        q=data['question']
        if question is None:question=deepcopy(q)
        for key in ('id','target_bits','group_sizes','depth','dummy_ratio'):
            if question[key]!=q[key]:raise ValueError('incompatible business question '+key)
        if q['dummy_ratio']<=1 or len(q['target_bits'])!=1:raise ValueError('dummy single-business mode only')
        budgets.add(q['dummy_budget'])
        provenance.append({'path':str(path),'sha256':hashlib.sha256(raw).hexdigest(),
                           'backend_sha256':hashlib.sha256(audit_path.read_bytes()).hexdigest()})
        checked={str((path.parent/r['config']).resolve()):r for r in audit['records']}
        for original in data['candidates']:
            row=deepcopy(original);config=(path.parent/row['config']).resolve()
            if str(config) not in checked or not checked[str(config)]['conditional_correctness']:
                raise ValueError('candidate not in passed backend audit')
            identity=(row['method'],row['candidate_id'])
            if identity in seen:
                if row['branches']!=seen[identity]['branches']:raise ValueError('candidate identity collision')
                seen[identity]['dummy_budget_origins'].append(q['dummy_budget']);continue
            row['config']=str(config);row['dummy_budget_origins']=[q['dummy_budget']]
            row['source_priority_file']=str(path);rows.append(row);seen[identity]=row
            check=deepcopy(checked[str(config)]);check['config']=str(config);checks.append(check)
    if not rows:raise ValueError('empty dummy pool')
    question['dummy_budget']=None;question['dummy_budget_options']=sorted(budgets)
    data={'schema':'new-stage-public-priorities-v1','question':question,'candidates':rows,
          'source_priority_files':provenance,'export_mode':'union_of_checked_budget_fronts',
          'HE_observations_used_for_selection':0,
          'scope':'union of preregistered dummy budgets; select at most two after exact security filtering'}
    audit={'schema':'backend-plan-exact-crosscheck-v1','records':checks,'all_pass':True,
           'HE_executions':0,'security_estimated':False,'scope':'references existing passed backend checks, no HE'}
    return data,audit


def main():
    a=argparse.ArgumentParser();a.add_argument('--out',required=True);a.add_argument('sources',nargs='+');v=a.parse_args()
    data,audit=combine(v.sources);out=Path(v.out);out.mkdir()
    for name,obj in [('priorities.json',data),('backend_crosscheck.json',audit)]:
        with (out/name).open('x') as f:json.dump(obj,f,indent=2);f.write('\n')
    print('combined',len(data['candidates']),'public candidates; HE executions 0')


if __name__=='__main__':main()
