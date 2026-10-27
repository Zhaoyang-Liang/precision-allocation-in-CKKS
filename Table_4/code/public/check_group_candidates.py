"""Public ordinary-split completion for the first new representative question.

Generates independent-N and genuine shared-prefix alternatives, preserving all
failures. This is the small representative stage, not the final whole matrix.
"""
import argparse
import gzip
import hashlib
import itertools
import json
from pathlib import Path

from profile_selection import question,scan,to_go_config
from group_selection import rebind_groups,limited_representatives,shared_prefix_candidates,combined_record


def main():
    a=argparse.ArgumentParser();a.add_argument('--joint-summary',required=True);a.add_argument('--out',required=True)
    v=a.parse_args();out=Path(v.out);out.mkdir()
    source=Path(v.joint_summary);joint=json.loads(source.read_text())
    q=question('A_h96_l32_d4',[96,32],[8192,8192])
    if joint['question']['target_bits']!=q['target_bits'] or joint['question']['depth']!=4:
        raise ValueError('representative source mismatch')
    ordinary=next(x for x in joint['results'] if x['method']=='ordinary')
    high=[rebind_groups(r,q,(0,)) for rows in ordinary['fronts_by_N'].values() for r in rows]
    high_choices=limited_representatives(high)
    family=joint['family']
    with gzip.open(out/'all_low_and_shared_candidates.jsonl.gz','xt') as log:
        low_scan=scan(q,False,(1,),family['N'],family['base_offsets'],family['shapes'],family['output_slack_bits'],family['P_counts'],family['P_prime_widths'],log)
        low=[r for rows in low_scan['fronts_by_N'].values() for r in rows]
        low_choices=limited_representatives(low)
        prefix=[]
        for entry in high_choices:
            h=entry['row']
            result=shared_prefix_candidates(h,q,(1,),family['base_offsets'],log)
            result['anchor']=h;prefix.append(result)
            print('shared anchor',h['id'],'tested',result['tested'],'passed',result['conditional_passes'],flush=True)
    combos=[];lookup={r['id']:r for r in high+low}
    for h,l in itertools.product(high_choices,low_choices):
        combos.append(combined_record(q,[h['row'],l['row']],'ordinary_split_independent'))
    for entry in prefix:
        for l in entry['front']:
            lookup[l['id']]=l
            combos.append(combined_record(q,[entry['anchor'],l],'ordinary_split_prefix_shared'))
    summary={'schema':'new-ordinary-grouping-completion-v1','question':q,
             'joint_source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
             'scope':'First representative; independent groups keep three declared public priorities per N, shared prefixes use a declared scale window. No global optimization claim.',
             'security_estimated':False,'HE_executions':0,'low_scan':low_scan,
             'shared_prefix_searches':prefix,'combined_candidates':combos}
    with (out/'summary.json').open('x') as f:json.dump(summary,f,indent=2);f.write('\n')
    # Public backend validation only: one shared/independent example per N pair.
    # Limit to 6 representative checks, not 6 measurements.
    for method in ('ordinary_split_independent','ordinary_split_prefix_shared'):
        candidates=sorted((r for r in combos if r['method']==method),key=lambda r:(r['resources']['relin_bytes'],r['id']))
        selected=[];seen=set()
        for row in candidates:
            signature=tuple(b['N'] for b in row['branches'])
            if signature in seen:continue
            seen.add(signature);selected.append(row)
            if len(selected)==3:break
        for index,row in enumerate(selected):
            config=to_go_config(q,method,[lookup[i] for i in row['branch_candidates']])
            with (out/f'{method}_{index}_public_config.json').open('x') as f:json.dump(config,f,indent=2);f.write('\n')
    print('independent group choices',len(high_choices),len(low_choices),'combined candidates',len(combos),'HE executions 0')


if __name__=='__main__':main()
