"""Sequential, resumable PUBLIC scan/refinement/backend planning only.

Each step has a start and completion record. An incomplete output directory is
never silently overwritten or rerun. The commands are fixed to three public
entry points; this driver cannot generate keys or execute HE.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def step(directory,name,script,args,outputs):
    started=directory/(name+'_started.json');finished=directory/(name+'_completed.json')
    program=ROOT/'public'/script
    command=[sys.executable,str(program),*map(str,args)]
    current={'command':command,'program_sha256':digest(program),'HE_executions':0}
    current['input_file_sha256']={str(Path(p).resolve()):digest(p) for p in args if Path(str(p)).is_file()}
    if finished.exists():
        previous=json.loads(finished.read_text())
        if previous['command']!=command or previous['program_sha256']!=current['program_sha256']:
            raise ValueError('public step program/command changed: '+name)
        if previous.get('input_file_sha256')!=current['input_file_sha256']:
            raise ValueError('public step input changed or predates input hashing: '+name)
        if any(digest(p)!=h for p,h in previous['output_sha256'].items()):
            raise ValueError('public output changed: '+name)
        print('reuse completed public step',name,flush=True);return
    if started.exists():raise ValueError('inspect incomplete public step before retrying: '+str(started))
    with started.open('x') as f:json.dump(current,f,indent=2);f.write('\n')
    with (directory/(name+'.log')).open('x') as log:
        result=subprocess.run(command,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
    if result.returncode:raise RuntimeError('public step failed; retained log: '+name)
    if callable(outputs):outputs=outputs()
    current['output_sha256']={str(Path(p).resolve()):digest(p) for p in outputs}
    with finished.open('x') as f:json.dump(current,f,indent=2);f.write('\n')
    print('completed public step',name,flush=True)


def main():
    a=argparse.ArgumentParser();a.add_argument('--question-id',required=True)
    a.add_argument('--dummy-budget',type=int,default=0)
    a.add_argument('--method',choices=['ordinary','allocated','both'],required=True)
    a.add_argument('--out',required=True);a.add_argument('--existing-coarse')
    v=a.parse_args();out=Path(v.out).resolve();out.mkdir(exist_ok=True)
    if v.existing_coarse:coarse=Path(v.existing_coarse).resolve()
    else:
        coarse=out/'coarse'
        step(out,'01_scan','profile_selection.py',
             ['--question-id',v.question_id,'--dummy-budget',v.dummy_budget,'--method',v.method,'--out',coarse],
             [coarse/'summary.json',coarse/'all_candidates.jsonl.gz'])
    summary=json.loads((coarse/'summary.json').read_text());q=summary['question']
    expected=['ordinary','allocated'] if v.method=='both' else [v.method]
    if q['id']!=v.question_id or q['dummy_budget']!=v.dummy_budget or [b['method'] for b in summary['results']]!=expected:
        raise ValueError('coarse question/method/budget mismatch')
    refined=out/'refined'
    step(out,'02_refine','refine_candidates.py',[coarse/'summary.json',refined],
         [refined/'summary.json',refined/'all_refined_candidates.jsonl.gz'])
    exported=out/'allfront'
    step(out,'03_export','export_stage_candidates.py',[refined/'summary.json',exported,'--all-front'],
         lambda:[exported/'priorities.json',*sorted(exported.glob('*_public_config.json'))])
    configs=sorted(exported.glob('*_public_config.json'))
    step(out,'04_backend','check_backend_plans.py',[exported],
         [exported/'backend_crosscheck.json',*configs,
          *(p.with_name(p.stem+'_plan.json') for p in configs),
          *(p.with_name(p.stem+'_certificate.json') for p in configs)])
    print('PUBLIC batch complete; HE executions 0; candidates',len(configs),flush=True)


if __name__=='__main__':main()
