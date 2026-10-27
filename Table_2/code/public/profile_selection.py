"""Finite candidate generator and public screen; never an HE/security claim.

The same scale/Q/P family is offered to ordinary and allocated representations.
No historical HE runner is invoked. Candidates are retained per ring dimension
until real lattice-estimator evidence is available: a small, insecure N must not
dominate and erase a larger valid N. Failed bounds and exact parameters persist.
"""
import argparse
from fractions import Fraction as F
from functools import lru_cache
import hashlib
import gzip
import itertools
import json
import math
from pathlib import Path
import time

from profile_certificate import branch_certificate, metadata_layers, bits_display
from selector import allocate_primes, balanced_widths, pow2, floor_log2
from multipliers import design_profile, design_quadratic_profile

ROOT=Path(__file__).resolve().parents[1]


@lru_cache(None)
def multiplier(profile,quadratic_exponent=None):
    if len(set(profile))==1 and quadratic_exponent is None:
        return None
    data=design_profile(profile) if quadratic_exponent is None else design_quadratic_profile(profile,quadratic_exponent)
    keys=('period','coefficients','inverse_coefficients','embedding_intervals','construction_sha256')
    return {k:data[k] for k in keys}


def partitions(values):
    """Each set partition once; used for ordinary grouping of precision classes."""
    values=tuple(values)
    if not values:
        yield ()
        return
    first,*rest=values
    for p in partitions(rest):
        yield ((first,),)+p
        for i in range(len(p)):
            yield p[:i]+((first,)+p[i],)+p[i+1:]


def precision_partitions(targets):
    classes={}
    for i,t in enumerate(targets):classes.setdefault(t,[]).append(i)
    out=[]
    for p in partitions(tuple(classes)):
        out.append(tuple(tuple(sorted(g for t in block for g in classes[t])) for block in p))
    return out


def question(qid,targets,sizes,depth=4,dummy_ratio=1,dummy_budget=0):
    if len(targets)!=len(sizes) or not targets or any(s<1 for s in sizes):
        raise ValueError('business dimensions')
    if not 1<=depth<=4 or dummy_ratio not in (1,2,4,8):raise ValueError('design domain')
    if dummy_ratio>1 and len(targets)!=1:raise ValueError('dummy model has one business group')
    return {'id':qid,'target_bits':list(targets),'group_sizes':list(sizes),
            'depth':depth,'dummy_ratio':dummy_ratio,'dummy_budget':dummy_budget}


def branch_design(q,groups,allocated):
    groups=tuple(groups)
    if allocated and q['dummy_ratio']>1:
        r=q['dummy_ratio']; profile=(q['target_bits'][0],)+(q['dummy_budget'],)*(r-1)
        pattern=[0]+[-1]*(r-1);m=multiplier(profile,q.get('quadratic_exponent'))
        ideal=F(sum(profile),r)
    elif allocated:
        profile=tuple(q['target_bits'][g] for g in groups)
        m=multiplier(profile,q.get('quadratic_exponent'));pattern=list(groups) if m else []
        ideal=F(sum(profile),len(profile))
    else:
        m=None;pattern=[];ideal=F(max(q['target_bits'][g] for g in groups))
    return {'groups':list(groups),'slot_pattern':pattern,'multiplier':m,'ideal_base':ideal}


def parameter_chain(n,base,depth,shape,slack,max_limb=60,input_amplitude=F(7,8),max_q_limbs=32):
    """Build backwards from nominal scales, then retain actual prime metadata."""
    if shape=='flat': nominal=[base]*(depth+1)
    elif shape=='alternating':nominal=[base+(8 if t%2 else 0) for t in range(depth+1)]
    elif shape=='deferred_terminal':nominal=[base]*depth+[2*base]
    else:raise ValueError('unknown finite schedule')
    # A + 1 allows dummy errors up to one; exact full-ring test decides later.
    threshold=2*pow2(nominal[-1])*(F(input_amplitude)**(2**depth)+1)
    out_bits=max(24,floor_log2(threshold)+1+slack)
    widths=balanced_widths(out_bits,max_limb)
    blocks=[]
    for t in range(depth):
        removed=2*nominal[t]-nominal[t+1]
        blocks.append([] if removed==0 else balanced_widths(removed,max_limb))
    for block in reversed(blocks):widths+=block
    if not 1 <= max_q_limbs <= 64:raise ValueError('Q_count_limit_outside_direct_square_contract')
    if len(widths)>max_q_limbs:raise ValueError('Q_count_exceeds_'+str(max_q_limbs))
    q=allocate_primes(n,widths)
    counts=list(map(len,blocks))
    return q,counts,nominal,metadata_layers(q,counts,pow2(nominal[0]))


def branch_resources(b, sizes, allocated):
    n=b['N'];slots=n//2;pattern=b['slot_pattern'];groups=b['groups']
    effective=sum(sizes[g] for g in groups)
    if pattern:
        capacity={g:pattern.count(g)*(slots//len(pattern)) for g in groups}
        batches=max((sizes[g]+capacity[g]-1)//capacity[g] for g in groups)
    else:batches=(effective+slots-1)//slots
    L=len(b['Q']);m=len(b['P']);active=L;work=[]
    for c in b['rescale_counts']:
        work.append(active);active-=c
    active-=b['output_drop_primes']
    blocks=[(l+m-1)//m for l in work]
    # These are explicit structural proxies, never predicted milliseconds.
    product_words=n*batches*sum(work)
    correction=n*batches*(3*sum(work)+2*active) if allocated else 0
    ks_words=n*batches*sum((block+2)*(l+m) for l,block in zip(work,blocks))
    return {'batches':batches,'effective_results':effective,'physical_slots':slots*batches,
            'business_utilization':str(F(effective,slots*batches)),
            'work_Q_counts':work,'decomposition_blocks':blocks,
            'square_Q_words':product_words,'public_correction_words':correction,
            'ks_transform_word_proxy':ks_words,
            'relin_bytes':16*n*((L+m-1)//m)*(L+m),
            'public_key_bytes':16*n*(L+m),'input_bytes':16*n*L*batches,
            'output_bytes':16*n*active*batches,
            'QP_log2_ceiling':(math.prod(map(int,b['Q']+b['P']))-1).bit_length()}


def contract_branch(spec,design,n,q,p,counts,scale_bits):
    return {'id':spec,'groups':design['groups'],'slot_pattern':design['slot_pattern'],
            'N':n,'Q':list(map(str,q)),'P':list(map(str,p)),
            'initial_scale_bits':scale_bits,'rescale_counts':counts,'output_drop_primes':0,
            'multiplier':design['multiplier'] or {'period':1,'coefficients':['1'],
                'inverse_coefficients':['1'],'embedding_intervals':[{'lower':'1','upper':'1'}]}}


def dominance_vector(row):
    r=row['resources']
    return (r['square_Q_words'],r['ks_transform_word_proxy'],r['public_correction_words'],
            r['relin_bytes'],r['public_key_bytes'],r['output_bytes'],r['QP_log2_ceiling'])


def pareto(rows):
    """Call per N: security checks must precede any cross-N dominance decision."""
    answer=[]
    for row in sorted(rows,key=lambda r:(dominance_vector(r),r['id'])):
        v=dominance_vector(row)
        if any(all(a<=b for a,b in zip(dominance_vector(old),v)) for old in answer):continue
        answer=[old for old in answer if not all(a<=b for a,b in zip(v,dominance_vector(old)))]
        answer.append(row)
    return answer


def to_go_config(q,method,selected,repeat=1):
    """Only emits numerical_only configuration; formal runner refuses it yet."""
    branches=[]
    for item in selected:
        b=item['branch'];m=b['multiplier']
        row={'id':b['id'],'groups':b['groups'],'parameters':{'log_n':b['N'].bit_length()-1,
              'q':b['Q'],'p':b['P'],'default_scale_bits':min(60,b['initial_scale_bits'])},
             'scale_bits':b['initial_scale_bits'],'rescale_counts':b['rescale_counts'],'output_drop_primes':b['output_drop_primes']}
        if b['slot_pattern']:row['slot_pattern']=b['slot_pattern']
        if m['period']>1:row['multiplier']=m
        branches.append(row)
    return {'schema':'ckks-profile-experiment-v1','id':q['id']+'_'+method+'_r'+str(repeat),
            'question_id':q['id'],'repeat':repeat,'plaintext_seed':str(2026100200+repeat),
            'encoder_decode_bits':1024,'depth':q['depth'],'target_bits':q['target_bits'],
            'group_sizes':q['group_sizes'],'branches':branches,'certification_status':'numerical_only'}


def from_matrix(matrix,question_id,dummy_budget=0):
    raw=next((x for x in matrix['questions'] if x['id']==question_id),None)
    if raw is None:raise ValueError('unregistered question ID')
    ratio=raw.get('slots_per_effective_message',1)
    if ratio>1 and dummy_budget not in raw['dummy_internal_error_budget_bits']:
        raise ValueError('unregistered internal dummy budget')
    return question(raw['id'],raw['targets_bits'],raw.get('group_sizes',[raw['effective_messages']]),
                    raw['depth'],ratio,dummy_budget)


def scan(q,allocated,groups,dimensions,offsets,shapes,slacks,p_counts,p_widths,stream):
    design=branch_design(q,groups,allocated);rows=[];stats={};start=time.monotonic()
    base0=math.ceil(design['ideal_base']/4)*4
    method='allocated' if allocated else 'ordinary'
    for n,offset,shape,slack in itertools.product(dimensions,offsets,shapes,slacks):
        base=max(24,base0+offset)
        try:primes,counts,nominal,_=parameter_chain(n,base,q['depth'],shape,slack)
        except ValueError as e:
            stats[str(e)]=stats.get(str(e),0)+1
            stream.write(json.dumps({'stage':'chain_generation','N':n,'base':base,'shape':shape,'slack':slack,
                                     'conditional_correctness':False,'reasons':[str(e)],'HE_executions':0})+'\n')
            continue
        for m,width in itertools.product(p_counts,p_widths):
            try:aux=allocate_primes(n,[width]*m,primes)
            except ValueError as e:
                stats[str(e)]=stats.get(str(e),0)+1
                stream.write(json.dumps({'stage':'P_generation','N':n,'base':base,'shape':shape,'slack':slack,
                                         'p_count':m,'p_width':width,'conditional_correctness':False,
                                         'reasons':[str(e)],'HE_executions':0})+'\n')
                continue
            bid=f'{method}_g'+''.join(map(str,groups))
            b=contract_branch(bid,design,n,primes,aux,counts,nominal[0])
            tag=f'{bid}_n{n.bit_length()-1}_b{base}_{shape}_s{slack}_p{m}x{width}'
            resources=branch_resources(b,q['group_sizes'],design['multiplier'] is not None)
            record={'id':tag,'branch':b,'shape':shape,'nominal_scales':nominal,
                    'parameter_recipe':{'base':base,'shape':shape,'slack':slack,'p_count':m,'p_width':width},
                    'resources':resources,'security_estimated':False,'HE_executions':0}
            try:
                cert=branch_certificate(b,1024,q['target_bits'],q['depth'])
                record.update({'conditional_correctness':cert['pass'],'reasons':cert['reasons'],
                               'group_errors':cert['group_errors'],
                               'max_range_ratio':max(cert['range_ratios_upper'],key=F)})
            except (ValueError,ArithmeticError) as e:
                record.update({'conditional_correctness':False,'reasons':['certificate_exception:'+str(e)]})
            for reason in record['reasons']:stats[reason]=stats.get(reason,0)+1
            stream.write(json.dumps(record,separators=(',',':'))+'\n')
            if record['conditional_correctness']:rows.append(record)
    fronts={str(n):pareto([r for r in rows if r['branch']['N']==n]) for n in dimensions}
    return {'method':method,'groups':list(groups),'conditional_passes':len(rows),
            'failure_counts':stats,'fronts_by_N':fronts,'wall_seconds':time.monotonic()-start,
            'security_estimated':False,'HE_executions':0}


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--out',required=True)
    ap.add_argument('--case',choices=['A','B','C'],default='A')
    ap.add_argument('--matrix',default=str(ROOT/'inherited/legacy_design/experiment_matrix_v3.json'))
    ap.add_argument('--question-id',help='use an exact ID from the frozen V3 question matrix')
    ap.add_argument('--dummy-budget',type=int,default=0)
    ap.add_argument('--method',choices=['ordinary','allocated','both'],default='both')
    ap.add_argument('--quadratic-exponent',type=int,help='explicit quadratic alternative for a two-level alternating allocated profile')
    ap.add_argument('--pilot',action='store_true',help='small PUBLIC plumbing check, not final parameter selection')
    a=ap.parse_args();out=Path(a.out);out.mkdir()
    q={'A':question('A_96_32_d4',[96,32],[8192,8192]),
       'B':question('B_160_32_32_32',[160,32,32,32],[4096]*4),
       'C':question('C_M1024_B160_r8',[160],[1024],dummy_ratio=8)}[a.case]
    if a.question_id:q=from_matrix(json.loads(Path(a.matrix).read_text()),a.question_id,a.dummy_budget)
    if a.quadratic_exponent is not None:q['quadratic_exponent']=a.quadratic_exponent
    dimensions=[16384,32768] if a.pilot else [4096,8192,16384,32768,65536]
    offsets=[28,36] if a.pilot else list(range(24,45,4))
    shapes=['flat'] if a.pilot else ['flat','alternating','deferred_terminal']
    slacks=[2] if a.pilot else [2,6]
    p_counts=[2,3,4,6] if a.pilot else list(range(1,11))
    p_widths=[60] if a.pilot else list(range(24,61,4))
    record={'schema':'new-public-candidate-scan-v1','question':q,'pilot_only':a.pilot,
            'family':{'N':dimensions,'base_offsets':offsets,'shapes':shapes,'output_slack_bits':slacks,
                      'P_counts':p_counts,'P_prime_widths':p_widths},
            'source_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(__file__).parent.glob('*.py')},
            'HE_executions':0,'security_estimated':False,'results':[]}
    with gzip.open(out/'all_candidates.jsonl.gz','xt') as stream:
        for allocated in ([False,True] if a.method=='both' else [a.method=='allocated']):
            result=scan(q,allocated,tuple(range(len(q['target_bits']))),dimensions,offsets,shapes,slacks,p_counts,p_widths,stream)
            record['results'].append(result)
            print(result['method'],'conditional passes:',result['conditional_passes'],flush=True)
    with (out/'summary.json').open('x') as f:json.dump(record,f,indent=2);f.write('\n')
    # Backend plan cross-check configurations from the pilot fronts. Still no HE.
    for result in record['results']:
        for n,front in result['fronts_by_N'].items():
            if front:
                chosen=min(front,key=lambda r:sum(dominance_vector(r)[:3]))
                config=to_go_config(q,result['method'],[chosen])
                with (out/f"{result['method']}_N{n}_public_config.json").open('x') as f:json.dump(config,f,indent=2);f.write('\n')
