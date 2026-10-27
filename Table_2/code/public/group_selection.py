"""Ordinary grouped candidates, including REAL prefix key sharing.

Different N/P or a non-prefix Q do not share keys. Resource aggregation mirrors
the Go runner's actual allocation rule. This module does not call these
structural counters runtime, and never prunes across unestimated dimensions.
"""
from copy import deepcopy
from fractions import Fraction as F
import hashlib
import json
from collections import defaultdict

from profile_selection import branch_design, branch_resources, contract_branch, pareto
from profile_certificate import branch_certificate
from selector import pow2, round_binary, floor_log2


def prefix_compatible(a,b):
    return a['N']==b['N'] and a['P']==b['P'] and len(a['Q'])>=len(b['Q']) and a['Q'][:len(b['Q'])]==b['Q']


def combined_resources(rows,sizes):
    branches=[x['branch'] for x in rows]
    assigned=[g for b in branches for g in b['groups']]
    if len(assigned)!=len(set(assigned)) or set(assigned)!=set(range(len(sizes))):
        raise ValueError('combined layout does not partition independent business groups')
    families=[];resources=[]
    for b in sorted(branches,key=lambda b:-len(b['Q'])):
        resource=branch_resources(b,sizes,b['multiplier']['period']>1)
        resources.append(resource)
        family=next((f for f in families if prefix_compatible(f['provider'],b)),None)
        if family is None:
            family={'provider':b,'branches':[],
                    'relin_bytes':resource['relin_bytes'],'public_key_bytes':resource['public_key_bytes']}
            families.append(family)
        family['branches'].append(b['id'])
    keys=('effective_results','physical_slots','batches','square_Q_words','public_correction_words',
          'ks_transform_word_proxy','input_bytes','output_bytes')
    total={k:sum(r[k] for r in resources) for k in keys}
    total['relin_bytes']=sum(f['relin_bytes'] for f in families)
    total['public_key_bytes']=sum(f['public_key_bytes'] for f in families)
    total['key_family_count']=len(families)
    total['key_families']=[{'provider_branch':f['provider']['id'],'branches':f['branches'],
                           'N':f['provider']['N'],'relin_bytes':f['relin_bytes'],
                           'public_key_bytes':f['public_key_bytes']} for f in families]
    total['security_cases']=[{'N':f['provider']['N'],'Q':f['provider']['Q'],'P':f['provider']['P'],
                             'scope':'maximum QP held under this shared secret'} for f in families]
    total['preflight_memory_guard_bytes']=4*sum(total[k] for k in ('input_bytes','output_bytes','relin_bytes','public_key_bytes'))
    total['business_utilization']=str(F(total['effective_results'],total['physical_slots']))
    total['security_estimated']=False
    return total


def rebind_groups(row,question,groups):
    """Reuse a public parameter candidate, but recompute its new workload/bounds."""
    b=deepcopy(row['branch']);b['groups']=list(groups);b['id']='ordinary_g'+''.join(map(str,groups))
    if b['multiplier']['period']!=1:raise ValueError('ordinary rebind only')
    certificate=branch_certificate(b,1024,question['target_bits'],question['depth'])
    return {'id':row['id']+'_for_'+b['id'],'branch':b,'shape':row.get('shape','imported'),
            'resources':branch_resources(b,question['group_sizes'],False),
            'conditional_correctness':certificate['pass'],'reasons':certificate['reasons'],
            'group_errors':certificate['group_errors'],'security_estimated':False,'HE_executions':0}


def limited_representatives(rows):
    """Three declared public priorities, per N; not the final measured choices."""
    by_n=defaultdict(list)
    for row in rows:
        if row['conditional_correctness']:by_n[row['branch']['N']].append(row)
    chosen=[]
    for n,candidates in sorted(by_n.items()):
        priorities=(lambda r:(r['resources']['square_Q_words']+r['resources']['ks_transform_word_proxy'],r['resources']['relin_bytes'],r['id']),
                    lambda r:(r['resources']['relin_bytes']+r['resources']['public_key_bytes'],r['resources']['ks_transform_word_proxy'],r['id']),
                    lambda r:(r['resources']['QP_log2_ceiling'],r['resources']['ks_transform_word_proxy'],r['id']))
        selected={}
        for i,priority in enumerate(priorities):
            row=min(candidates,key=priority)
            selected.setdefault(row['id'],{'row':row,'priorities':[]})['priorities'].append(i)
        chosen.extend(selected.values())
    return chosen


def prefix_schedules(q,initial_bits,depth,window=(-16,24)):
    """Finite rescale family using exact metadata, including delayed final rescale.

    Intermediate scales stay in an explicitly declared log2 window around the
    initial scale. This is a candidate generator, NOT a necessary condition.
    Final layer additionally permits the doubled-scale window. Full correctness
    is checked afterwards, without assuming intermediate coefficient no-wrap.
    """
    def visit(L,D,counts):
        t=len(counts);squared=round_binary(D*D,1024);nextD=squared
        for count in range(L):
            if count:nextD=round_binary(nextD/q[L-count],1024)
            exponent=floor_log2(nextD)
            allowed=initial_bits+window[0]<=exponent<=initial_bits+window[1]
            if t==depth-1:
                allowed|=count==0 or 2*initial_bits+window[0]<=exponent<=2*initial_bits+window[1]
            if not allowed:continue
            path=counts+(count,)
            if t==depth-1:yield path
            else:yield from visit(L-count,nextD,path)
    yield from visit(len(q),pow2(initial_bits),())


def shared_prefix_candidates(anchor,question,groups,offsets,stream):
    """Keep the anchor's exact N/P; low groups may use any Q prefix in this family."""
    a=anchor['branch'];n=a['N'];aux=tuple(map(int,a['P']));all_q=tuple(map(int,a['Q']))
    design=branch_design(question,groups,False);base0=max(question['target_bits'][g] for g in groups)
    rows=[];tested=0
    for L in range(1,len(all_q)+1):
        q=all_q[:L]
        for offset in offsets:
            base=base0+offset
            for counts in prefix_schedules(q,base,question['depth']):
                bid='ordinary_g'+''.join(map(str,groups))
                b=contract_branch(bid,design,n,q,aux,list(counts),base)
                digest=hashlib.sha256(json.dumps(b,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                certificate=branch_certificate(b,1024,question['target_bits'],question['depth'])
                row={'id':'prefix_'+digest[:20],'branch':b,'anchor_candidate':anchor['id'],
                     'shape':'explicit_prefix_schedule','conditional_correctness':certificate['pass'],
                     'reasons':certificate['reasons'],'group_errors':certificate['group_errors'],
                     'resources':branch_resources(b,question['group_sizes'],False),
                     'security_estimated':False,'HE_executions':0}
                stream.write(json.dumps(row,separators=(',',':'))+'\n');tested+=1
                if row['conditional_correctness']:rows.append(row)
    return {'tested':tested,'conditional_passes':len(rows),'front':pareto(rows),
            'scope':'same N/P and exact Q prefix; finite intermediate scale window, not exhaustive algorithm optimization'}


def combined_record(question,rows,method):
    resources=combined_resources(rows,question['group_sizes'])
    tag=hashlib.sha256(json.dumps([r['id'] for r in rows],separators=(',',':')).encode()).hexdigest()[:20]
    return {'id':method+'_'+tag,'method':method,'question_id':question['id'],
            'branch_candidates':[r['id'] for r in rows],'branches':[r['branch'] for r in rows],
            'resources':resources,'conditional_correctness':all(r['conditional_correctness'] for r in rows),
            'security_estimated':False,'HE_executions':0}
