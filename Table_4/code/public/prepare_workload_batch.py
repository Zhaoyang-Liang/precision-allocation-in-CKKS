"""Rebind several dummy-budget fronts to one registered business count."""
import argparse
import json
from pathlib import Path
from prepare_profile_batch import step


def main():
    a=argparse.ArgumentParser();a.add_argument('--question-id',required=True);a.add_argument('--out',required=True)
    a.add_argument('summaries',nargs='+');v=a.parse_args();out=Path(v.out).resolve();out.mkdir(exist_ok=True)
    seen=set();priorities=[]
    for filename in v.summaries:
        source=Path(filename).resolve();data=json.loads(source.read_text());budget=data['question']['dummy_budget']
        if budget in seen:raise ValueError('duplicate internal dummy budget')
        seen.add(budget);prefix='b'+str(budget);rebound=out/(prefix+'_rebound')
        step(out,prefix+'_01_rebind','rebind_workload.py',[source,v.question_id,rebound],[rebound/'summary.json'])
        exported=out/(prefix+'_allfront')
        step(out,prefix+'_02_export','export_stage_candidates.py',[rebound/'summary.json',exported,'--all-front'],
             lambda e=exported:[e/'priorities.json',*sorted(e.glob('*_public_config.json'))])
        configs=sorted(exported.glob('*_public_config.json'))
        step(out,prefix+'_03_backend','check_backend_plans.py',[exported],
             [exported/'backend_crosscheck.json',*configs,
              *(p.with_name(p.stem+'_plan.json') for p in configs),
              *(p.with_name(p.stem+'_certificate.json') for p in configs)])
        priorities.append(exported/'priorities.json')
    combined=out/'combined'
    step(out,'99_combine','combine_priorities.py',['--out',combined,*priorities],
         [combined/'priorities.json',combined/'backend_crosscheck.json'])
    print('workload batch complete',v.question_id,'HE executions 0',flush=True)


if __name__=='__main__':main()
