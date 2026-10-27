"""All precision-class partitions, with independent and shared-prefix choices.

The finite branch family is identical to the joint scan. Three public
representatives per N/block are retained before combinations; this is a
declared finite baseline family, not a global optimizer.
"""
import argparse
import gzip
import itertools
import json
from pathlib import Path

from profile_selection import question, scan, precision_partitions
from refine_candidates import refine
from group_selection import rebind_groups, limited_representatives, shared_prefix_candidates, combined_record
from export_stage_candidates import orders


def main():
    ap=argparse.ArgumentParser();ap.add_argument('joint_summary');ap.add_argument('out');ap.add_argument('--cache',required=True)
    args=ap.parse_args();out=Path(args.out);out.mkdir();cache=Path(args.cache);cache.mkdir(exist_ok=True)
    joint=json.loads(Path(args.joint_summary).read_text());q=joint['question'];family=joint['family']
    ordinary=next(b for b in joint['results'] if b['method']=='ordinary')
    maximum=max(q['target_bits']);pools={}
    partitions=([((0,),(1,))] if q['id'].startswith('A_') else [p for p in precision_partitions(q['target_bits']) if len(p)>1])
    groups=sorted({tuple(g) for p in partitions for g in p})
    for group in groups:
        target=max(q['target_bits'][g] for g in group)
        if target==maximum:
            block=ordinary
        else:
            dest=cache/f't{target}_d{q["depth"]}.json'
            if dest.exists():block=json.loads(dest.read_text())['results'][0]
            else:
                single=question(f'branch_t{target}_d{q["depth"]}',[target],[8192],q['depth'])
                with gzip.open(cache/f't{target}_d{q["depth"]}_coarse.jsonl.gz','xt') as log:
                    block=scan(single,False,(0,),family['N'],family['base_offsets'],family['shapes'],family['output_slack_bits'],family['P_counts'],family['P_prime_widths'],log)
                source={'question':single,'family':family,'results':[block]}
                with gzip.open(cache/f't{target}_d{q["depth"]}_refinement.jsonl.gz','xt') as log:refined=refine(source,log)
                dest.write_text(json.dumps(refined));block=refined['results'][0]
        rebound=[rebind_groups(row,q,group) for front in block['fronts_by_N'].values() for row in front]
        pools[group]=[entry['row'] for entry in limited_representatives(rebound)]
        if not pools[group]:raise ValueError('empty branch family '+str(group))
    chosen={};attempts=0
    def retain(rows,organization):
        nonlocal attempts
        attempts+=1
        record=combined_record(q,rows,organization)
        if record['resources']['preflight_memory_guard_bytes']>8*2**30:return
        record['candidate_id']=record['id']
        record['security_parameters']=[{'qp_exact':str(__import__('math').prod(map(int,b['Q']+b['P'])))} for b in record['branches']]
        signature=(organization,tuple((tuple(b['groups']),b['N']) for b in record['branches']))
        for index,key in enumerate(orders()):
            old=chosen.get((signature,index))
            if old is None or key(record)<key(old):chosen[signature,index]=record
    with gzip.open(out/'shared_prefix_attempts.jsonl.gz','xt') as log:
        for pi,partition in enumerate(partitions):
            partition=tuple(sorted(partition,key=lambda g:-max(q['target_bits'][i] for i in g)))
            for rows in itertools.product(*(pools[tuple(g)] for g in partition)):
                retain(rows,f'independent_partition{pi}')
            anchor_group=tuple(partition[0])
            for anchor in pools[anchor_group]:
                lows=[]
                for group in partition[1:]:
                    result=shared_prefix_candidates(anchor,q,tuple(group),family['base_offsets'],log)
                    lows.append(result['front'])
                for tail in itertools.product(*lows):retain([anchor,*tail],f'shared_prefix_partition{pi}')
            print(q['id'],'partition',pi,'of',len(partitions),'combinations',attempts,flush=True)
    unique={r['id']:r for r in chosen.values()}
    summary={'schema':'new-ordinary-grouping-completion-v1','question':q,'family':family,
             'partitions':[list(map(list,p)) for p in partitions],
             'scope':'All precision-class partitions (A: explicit two-way split). Finite branch priorities and shared-prefix scale window. No HE timings used, no global optimality claim.',
             'combination_attempts':attempts,'combined_candidates':list(unique.values()),'HE_executions':0,'security_estimated':False}
    (out/'summary.json').write_text(json.dumps(summary))
    print('kept',len(unique),'pre-security public combinations')


if __name__=='__main__':main()
