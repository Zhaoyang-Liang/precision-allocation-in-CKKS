"""Export finite public priorities for joint, grouped and dummy experiments.

Selection is per dimension/layout organization BEFORE security estimates. No
HE timing is read. Parameter generation/failures remain in the source summary.
"""
import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
from group_selection import combined_resources
from profile_selection import to_go_config


def method_name(q,allocated,grouped=False):
    if q['id'].startswith('C_'):
        if allocated!=(q['dummy_ratio']>1):raise ValueError('C layout/method mismatch')
        return 'allocated_dummy' if allocated else 'ordinary_direct'
    if grouped:return 'ordinary_grouped' if q['id'].startswith('B_') else 'ordinary_split'
    return 'allocated_joint' if allocated else 'ordinary_joint'


def orders():
    return [lambda r:(sum(r['resources'][k] for k in ('square_Q_words','ks_transform_word_proxy','public_correction_words')),r['resources']['relin_bytes'],r['candidate_id']),
            lambda r:(r['resources']['relin_bytes']+r['resources']['public_key_bytes'],r['resources']['ks_transform_word_proxy'],r['candidate_id']),
            lambda r:(sum((int(c['qp_exact'])-1).bit_length() for c in r['security_parameters']),r['resources']['ks_transform_word_proxy'],r['candidate_id'])]


def rows_from_summary(summary):
    q=summary['question'];rows=[]
    if 'combined_candidates' in summary:
        candidates=[(r['id'],r['branches'],method_name(q,False,True),r['method'])
                    for r in summary['combined_candidates'] if r['conditional_correctness']]
    else:
        candidates=[(r['id'],[r['branch']],method_name(q,b['method']=='allocated'),b['method'])
                    for b in summary['results'] for front in b['fronts_by_N'].values()
                    for r in front if r['conditional_correctness']]
    import math
    for identity,branches,method,organization in candidates:
        selected=[{'branch':b} for b in branches]
        resource=combined_resources(selected,q['group_sizes'])
        parameters=[{'N':b['N'],'qp_exact':str(math.prod(map(int,b['Q']+b['P'])))} for b in branches]
        rows.append({'candidate_id':identity,'branches':branches,'method':method,'organization':organization,
                     'resources':resource,'security_parameters':parameters})
    return rows


def public_priorities(rows):
    by_layout=defaultdict(list)
    for r in rows:
        signature=(r['method'],r['organization'],tuple((tuple(b['groups']),b['N']) for b in r['branches']))
        by_layout[signature].append(r)
    chosen=[]
    for signature,pool in sorted(by_layout.items()):
        used={}
        for i,key in enumerate(orders()):
            r=min(pool,key=key)
            used.setdefault(r['candidate_id'],dict(r,public_priorities=[]))['public_priorities'].append(i)
        chosen.extend(used.values())
    return chosen


def all_front_candidates(rows):
    """Keep every already non-dominated single-branch source candidate.

    The source scan/refinement computes fronts separately for each N. Do not
    throw away a candidate for a better but not-yet-safe QP before estimation.
    Grouped source summaries can also be exported without additional pruning;
    their finite combination family is defined by the generating program.
    """
    seen=set();result=[]
    for row in rows:
        key=(row['method'],row['organization'],row['candidate_id'])
        if key in seen:continue
        seen.add(key);result.append(dict(row,public_priorities=['all_source_front']))
    return result


def main():
    a=argparse.ArgumentParser();a.add_argument('summary');a.add_argument('out')
    a.add_argument('--all-front',action='store_true',help='estimate all source front candidates before selecting priorities')
    v=a.parse_args()
    source=Path(v.summary).resolve();summary=json.loads(source.read_text());out=Path(v.out);out.mkdir()
    rows=(all_front_candidates if v.all_front else public_priorities)(rows_from_summary(summary));q=summary['question']
    for r in rows:
        tag=hashlib.sha256(r['candidate_id'].encode()).hexdigest()[:16]
        filename=r['method']+'_'+tag+'_public_config.json'
        config=to_go_config(q,r['method'],[{'branch':b} for b in r['branches']])
        with (out/filename).open('x') as f:json.dump(config,f,indent=2);f.write('\n')
        r['config']=filename
    result={'schema':'new-stage-public-priorities-v1','question':q,
            'source_summary':str(source),'source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'candidates':rows,'HE_observations_used_for_selection':0,
            'export_mode':'all_source_fronts' if v.all_front else 'three_public_priorities',
            'scope':('all finite source fronts retained through security filtering; not globally optimal parameters'
                     if v.all_front else 'finite pre-security priorities per N/layout, not globally optimal parameters'),
            'priorities':['arithmetic-word proxy including correction','combined key storage','total QP ceiling']}
    with (out/'priorities.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print('exported',len(rows),'public choices; HE executions 0')


if __name__=='__main__':main()
