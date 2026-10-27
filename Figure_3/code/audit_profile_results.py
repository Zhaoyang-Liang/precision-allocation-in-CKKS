"""Recompute NEW run statistics from raw decoded rationals, not reported bits.

This reads saved diagnostics, not secret keys, and does not rerun/decrypt HE.
The Go runner has already checked ciphertext serialization against its objects.
Here byte lengths and hashes are independently checked against retained files.
"""
import argparse
from collections import Counter
from fractions import Fraction as F
import gzip
import hashlib
import json
import math
from pathlib import Path
import struct


def exact_input(seed,group,index,family=None):
    if family is not None:
        if family not in ('grow','reciprocal'):raise ValueError('input family')
        if index<3:x=(F(1),F(2),F(3,2))[index]
        else:x=1+F(int.from_bytes(hashlib.sha256(struct.pack('<QQQ',seed,group,index)).digest(),'big'),2**256)
        return x if family=='grow' else 1/x
    if index<3:return (F(3,4),F(7,8),F(13,16))[index]
    data=struct.pack('<QQQ',seed,group,index)
    return F(3,4)+F(int.from_bytes(hashlib.sha256(data).digest(),'big'),2**259)


def error_bits(squared):
    return None if squared==0 else (math.log2(squared.denominator)-math.log2(squared.numerator))/2


def check(condition,message):
    if not condition:raise ValueError(message)


def audit(directory):
    directory=Path(directory)
    raw=(directory/'config.json').read_bytes();c=json.loads(raw)
    r=json.loads((directory/'result.json').read_text());p=json.loads((directory/'plan.json').read_text())
    check(r['schema']=='ckks-profile-result-v1','result schema')
    check(r['config_sha256']==hashlib.sha256(raw).hexdigest(),'configuration hash')
    check(r['contract_sha256']==p['contract_sha256'],'contract identity')
    check(r['status'] in ('completed','accuracy_failed'),'incomplete run must remain a failure')
    mappings=json.loads((directory/'business_mapping.json').read_text())
    maps={(m['branch'],m['batch']):m for m in mappings}
    check(len(maps)==len(mappings),'duplicate batch mapping')
    seen=set();maximum=[F(0)]*len(c['target_bits']);counts=[0]*len(maximum);passing=[0]*len(maximum)
    dummy_count=0;dummy_max=F(0);output_bytes=0;payload_bytes=0
    checked_outputs=set()
    for row in r['outputs']:
        key=(row['branch'],row['batch']);check(key in maps and key not in checked_outputs,'unexpected/duplicate output')
        checked_outputs.add(key);mapping=maps[key]
        assigned={v['slot']:(v['group'],v['business_index_in_group']) for v in mapping['values']}
        check(len(assigned)==len(mapping['values']),'duplicate mapped slot')
        path=directory/row['file'];data=path.read_bytes();meta=row['ciphertext']
        check(len(data)==int(meta['serialized_bytes']),'output byte count')
        check(hashlib.sha256(data).hexdigest()==meta['sha256'],'output hash')
        check(F(meta['wire_relative_scale_change_exact'])==0,'scale changed in wire format')
        payload=8*int(meta['n'])*int(meta['q_components'])*(int(meta['degree'])+1)
        check(payload==int(meta['coefficient_payload_bytes']),'native payload formula')
        output_bytes+=len(data);payload_bytes+=payload
        diagnostic=directory/f"{row['branch']}_batch{row['batch']}.decoded.jsonl.gz"
        slots=set()
        with gzip.open(diagnostic,'rt') as f:
            for line in f:
                v=json.loads(line);slot=v['slot']
                check(0<=slot<mapping['physical_slots'] and slot not in slots,'decoded slot coverage')
                slots.add(slot);re,im=F(v['real_exact']),F(v['imag_exact'])
                if slot in assigned:
                    g,i=assigned[slot];check(v['effective'] and (v['group'],v['business_index'])==(g,i),'business relabeling')
                    check((g,i) not in seen and 0<=g<len(maximum) and 0<=i<c['group_sizes'][g],'business coverage')
                    seen.add((g,i));x=exact_input(int(c['plaintext_seed']),g,i,c.get('input_family'))
                    truth=x**(2**c['depth']);sq=(re-truth)**2+im**2
                    maximum[g]=max(maximum[g],sq);counts[g]+=1
                    passing[g]+=sq<=F(1,2**(2*c['target_bits'][g]))
                else:
                    check(not v['effective'] and v['group']==-1 and v['business_index']==-1,'dummy credited as business')
                    dummy_count+=1;dummy_max=max(dummy_max,re*re+im*im)
        check(len(slots)==mapping['physical_slots'],'missing physical diagnostics')
    check(checked_outputs==set(maps),'missing batch')
    check(counts==c['group_sizes'],'missing group results')
    check(sum(counts)==r['effective_results'],'effective result count')
    check(output_bytes==int(r['output_serialized_bytes']) and payload_bytes==int(r['output_coefficient_payload_bytes']),'total output bytes')
    check(dummy_count==r['dummy_or_padding_slots_checked'] and dummy_max==F(r['dummy_max_complex_magnitude_squared']),'dummy diagnostics')
    for row in r['accuracy']:
        g=row['group'];check(row['checked_effective_results']==counts[g] and row['passing_effective_results']==passing[g],'reported accuracy count')
        check(F(row['max_complex_error_squared_exact_for_decoded_values'])==maximum[g],'reported exact maximum error')
        check(row['all_results_pass']==(counts[g]==passing[g]),'reported target pass')
    check(len(r['accuracy'])==len(maximum),'accuracy group rows')
    actual_pass=counts==passing
    check(actual_pass==r['all_effective_results_pass'],'whole run pass')
    check(r['status']==('completed' if actual_pass else 'accuracy_failed'),'failure must not be called completed')
    online=r['online'];phase_sum=sum(int(x['duration_ns']) for x in online['phases']);wall=int(online['wall_ns'])
    check(0<=phase_sum<=wall and phase_sum==int(online['phase_sum_ns']),'phase accounting')
    check(wall-phase_sum==int(online['outside_phases_ns']),'unattributed online time')
    ops=r['operations'];calls=Counter(x['kind'] for x in ops);totals=r['operation_totals']
    check(dict(calls)=={k:int(v) for k,v in totals['calls_by_kind'].items()},'operation call totals')
    expected_products=len(maps)*c['depth']
    check(calls['ciphertext_square']==expected_products and calls['relinearize']==expected_products,'missing batch/layer products')
    check(sum(o['key_switch_calls'] for o in ops)==int(totals['key_switch_calls'])==expected_products,'key switch count')
    check(sum(int(o.get('component_q_pointwise_products',0)) for o in ops)==int(totals['public_component_q_pointwise_products']),'public correction count')
    keys={}
    for key in r['keys']:
        if key['id'] in keys:check(keys[key['id']]==key,'inconsistent shared key')
        keys[key['id']]=key
    eval_payload=sum(int(k['coefficient_payload_bytes']) for k in keys.values() if k['kind']!='public')
    pk_payload=sum(int(k['coefficient_payload_bytes']) for k in keys.values() if k['kind']=='public')
    check(eval_payload==int(r['evaluation_key_coefficient_payload_bytes']) and pk_payload==int(r['public_key_coefficient_payload_bytes']),'key payload sharing')
    return {'schema':'independent-new-run-audit-v1','run':str(directory),'question_id':c['question_id'],
            'repeat':c['repeat'],'contract_sha256':p['contract_sha256'],'all_checks_pass':True,
            'business_accuracy_pass':actual_pass,'HE_executions_in_this_audit':0,
            'wall_ns':wall,'effective_results':sum(counts),
            'error_squared_max_by_group':list(map(str,maximum)),
            'precision_bits_display':[error_bits(x) for x in maximum],
            'output_payload_bytes':payload_bytes,'output_serialized_bytes':output_bytes,
            'evaluation_key_payload_bytes':eval_payload,'public_key_payload_bytes':pk_payload}


def summarize_pair(a,b):
    check({a['repeat'],b['repeat']}=={1,2},'exactly the two planned repeats required')
    check(a['contract_sha256']==b['contract_sha256'] and a['question_id']==b['question_id'],'cannot average different configurations')
    check(a['effective_results']==b['effective_results'],'different effective workload')
    for metric in ('output_payload_bytes','evaluation_key_payload_bytes','public_key_payload_bytes'):
        check(a[metric]==b[metric],'repeat changed structural resource '+metric)
    mean=F(a['wall_ns']+b['wall_ns'],2)
    errors=[max(F(x),F(y)) for x,y in zip(a['error_squared_max_by_group'],b['error_squared_max_by_group'],strict=True)]
    return {'schema':'new-two-repeat-summary-v1','question_id':a['question_id'],
            'contract_sha256':a['contract_sha256'],'repeat_count':2,
            'wall_ns_each':[a['wall_ns'],b['wall_ns']],'mean_wall_ns_exact':str(mean),
            'effective_results':a['effective_results'],
            'effective_results_per_second_from_mean':float(a['effective_results']*10**9/mean),
            'worst_precision_bits_display':[error_bits(x) for x in errors],
            'both_runs_accuracy_pass':a['business_accuracy_pass'] and b['business_accuracy_pass'],
            'output_payload_bytes':a['output_payload_bytes'],
            'evaluation_key_payload_bytes':a['evaluation_key_payload_bytes'],
            'public_key_payload_bytes':a['public_key_payload_bytes'],
            'scope':'Two local observations only; no statistical confidence or stable-speedup claim.'}


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('runs',nargs='+');ap.add_argument('--out',required=True);v=ap.parse_args()
    rows=[audit(p) for p in v.runs]
    result={'audits':rows,'pair_summary':summarize_pair(*rows) if len(rows)==2 else None}
    with Path(v.out).open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print('independent record checks passed; audited runs:',len(rows))
