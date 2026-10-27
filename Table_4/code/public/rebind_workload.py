"""Reuse a certified parameter family for another registered C workload.

No HE or timing is performed. Only effective message count may change. Work
and byte counters are recomputed, then actual Go plans must be rechecked.
Per-N single-branch dominance is preserved: every batch-dependent counter is
multiplied by the same positive batch ratio and key counters are unchanged.
"""
import argparse
from copy import deepcopy
from fractions import Fraction as F
import hashlib
import json
from pathlib import Path

from profile_selection import from_matrix,branch_resources
from profile_certificate import branch_certificate


def rebind(summary,new_question):
    old=summary['question'];new=new_question
    if not old['id'].startswith('C_') or not new['id'].startswith('C_'):
        raise ValueError('only registered single-business C questions can be rebound')
    if len(old['target_bits'])!=1 or len(new['target_bits'])!=1:
        raise ValueError('single business class required')
    for name in ('target_bits','depth','dummy_ratio','dummy_budget'):
        if old[name]!=new[name]:raise ValueError('workload reuse changes '+name)
    if old.get('quadratic_exponent')!=new.get('quadratic_exponent'):
        raise ValueError('multiplier construction changes')
    output=deepcopy(summary);output['question']=deepcopy(new)
    for block in output['results']:
        if block['groups']!=[0]:raise ValueError('single complete branch required')
        for front in block['fronts_by_N'].values():
            for row in front:
                b=row['branch']
                if b['groups']!=[0]:raise ValueError('branch covers different business groups')
                cert=branch_certificate(b,1024,new['target_bits'],new['depth'])
                if not cert['pass']:raise ValueError('unchanged mathematics failed recertification')
                before=row['resources']
                after=branch_resources(b,new['group_sizes'],b['multiplier']['period']>1)
                ratio=F(after['batches'],before['batches'])
                for key in ('square_Q_words','ks_transform_word_proxy','public_correction_words',
                            'input_bytes','output_bytes','physical_slots'):
                    if F(after[key])!=ratio*before[key]:raise ValueError('batch scaling mismatch '+key)
                for key in ('relin_bytes','public_key_bytes','QP_log2_ceiling'):
                    if before[key]!=after[key]:raise ValueError('key/context unexpectedly changed')
                row['resources']=after;row['group_errors']=cert['group_errors']
                row['workload_recertified']=True
    output['schema']='new-public-workload-rebinding-v1'
    output['original_question']=deepcopy(old)
    output['HE_executions']=0
    output['reuse_scope']='same single-branch parameters and mathematics; per-N front preserved, all workload counters recomputed'
    return output


def main():
    a=argparse.ArgumentParser();a.add_argument('summary');a.add_argument('question_id');a.add_argument('out')
    a.add_argument('--matrix',default=str(Path(__file__).resolve().parents[1]/'inherited/legacy_design/experiment_matrix_v3.json'))
    v=a.parse_args();source=Path(v.summary);summary=json.loads(source.read_text())
    q=from_matrix(json.loads(Path(v.matrix).read_text()),v.question_id,summary['question']['dummy_budget'])
    if 'quadratic_exponent' in summary['question']:q['quadratic_exponent']=summary['question']['quadratic_exponent']
    result=rebind(summary,q);result['source_summary']=str(source.resolve())
    result['source_sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
    result['program_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    out=Path(v.out);out.mkdir()
    with (out/'summary.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(v.question_id,'rebound; HE executions 0')


if __name__=='__main__':main()
