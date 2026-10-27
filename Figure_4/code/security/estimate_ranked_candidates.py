"""Find safe public priority minima without estimating irrelevant worse rows.

Within each declared priority, visit candidates in exact sorted order and stop
at the first passing candidate. Every skipped predecessor has an explicit
failure or missing-certificate reason. This is equivalent to taking the minimum
after filtering the whole finite pool, without assuming security monotonicity.
No timing observations or HE are read/executed.
"""
import argparse
from copy import deepcopy
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'public'))
from export_stage_candidates import orders
from estimate_cases import plan_cases,reusable_estimates


def ranked_select(rows,check):
    decisions=[]
    for method in sorted({r['method'] for r in rows}):
        pool=[r for r in rows if r['method']==method]
        for label,key in zip(('structural_proxy','key_storage'),orders()[:2]):
            visited=[];selected=None
            for row in sorted(pool,key=key):
                verdict=check(row)
                visited.append({'candidate_id':row['candidate_id'],**verdict})
                if verdict['pass']:
                    selected=row['candidate_id'];break
            decisions.append({'method':method,'priority':label,'selected_candidate_id':selected,
                              'visited_prefix':visited,'candidate_count':len(pool)})
    return decisions


def digest(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def rejection_witness(attacks,target=128):
    """One real finite attack below target suffices to reject, never to accept."""
    names={'primal_usvp','primal_bdd','dual_hybrid'}
    if not attacks or not set(attacks)<=names:raise ValueError('unknown rejection attacks')
    for name,attack in attacks.items():
        if 'rop' not in attack.get('cost',{}):raise ValueError('missing raw rejection cost')
        bits=float(attack['log2_rop'])
        if math.isnan(bits):raise ValueError('NaN rejection cost')
        if math.isfinite(bits) and bool(attack['target_pass'])!=(bits>=target):raise ValueError('inconsistent rejection cost')
        if math.isfinite(bits) and bits<target:return name
    return None


def main():
    a=argparse.ArgumentParser();a.add_argument('--plan',required=True);a.add_argument('--priorities',action='append',required=True)
    a.add_argument('--out',required=True);a.add_argument('--reuse',action='append',default=[])
    a.add_argument('--estimator',default='/Users/mac/opt/lattice-estimator');v=a.parse_args()
    out=Path(v.out).resolve()
    if out.exists():raise FileExistsError(out)
    wrapper=out.with_suffix('.wrapper.py')
    with wrapper.open('xb') as f:f.write(Path(__file__).read_bytes())
    plan_raw=Path(v.plan).read_bytes();all_cases=plan_cases(json.loads(plan_raw))
    exact=lambda c:(c['N'],tuple(c['Q']),tuple(c['P']))
    permitted={exact(c):c for c in all_cases}
    repository=Path(v.estimator).resolve()
    commit=subprocess.check_output(['git','-C',str(repository),'rev-parse','HEAD'],text=True).strip()
    dirty=subprocess.check_output(['git','-C',str(repository),'diff','--name-only','HEAD'],text=True).splitlines()
    if dirty:raise RuntimeError('estimator tracked files modified')
    sys.path.insert(0,str(repository))
    from sage.all import ZZ,oo,log
    from estimator import LWE,ND,RC
    attacks={'primal_usvp':LWE.primal_usvp,'primal_bdd':LWE.primal_bdd,'dual_hybrid':LWE.dual_hybrid}
    cache,provenance=reusable_estimates(v.reuse,commit,128)
    rejected_cache={}
    # reusable_estimates above has already validated every source model/version.
    for filename in v.reuse:
        source=Path(filename);data=json.loads(source.read_text())
        for row in data.get('early_rejections',[]):
            qp=math.prod(map(int,row['Q']+row['P']))
            if str(qp)!=row['qp_exact'] or (qp-1).bit_length()!=row['q_est_log2']:raise ValueError('rejection input mismatch')
            if rejection_witness(row['attacks']) is None:raise ValueError('no actual below-target rejection witness')
            rejected_cache[(row['N'],row['q_est_log2'])]={'attacks':row['attacks'],'origin_file_sha256':digest(source)}
    result={'schema':'ckks-new-security-v1','plan_sha256':hashlib.sha256(plan_raw).hexdigest(),
            'estimator_commit':commit,'estimator_tracked_dirty':dirty,'wrapper_sha256':digest(wrapper),
            'wrapper_source_file':str(wrapper),'model':'RC.MATZOV','secret':'uniform_ternary',
            'error_sigma':'3.2','actual_sampler_abs_bound':'19.2','samples':'infinity','target_bits':128,
            'HE_executions':0,'cases':[],'reused_result_files':provenance,'new_attack_calls':0,
            'reused_cases':0,'reported_log_precision':'estimator numerical costs, not a proof',
            'selection_scope':'exact priority minima over the supplied finite fronts, not minimum runtime or global CKKS optima',
            'priority_sources':[],'ranked_decisions':[],'early_rejections':[],
            'early_rejection_policy':'Stop only after a real finite attack estimate below target. Accepted cases retain all three complete attacks.'}
    completed={};case_log=out.with_suffix('.cases.jsonl')
    with case_log.open('x') as logstream:
        def estimate(case):
            ekey=exact(case)
            if ekey in completed:return completed[ekey]
            key=(case['N'],case['q_est_log2'])
            if key in rejected_cache:
                cached=rejected_cache[key]
                row=dict(case,attacks=cached['attacks'],all_three_attacks_pass=False,
                         rejection_witness=rejection_witness(cached['attacks']),
                         estimate_provenance={k:x for k,x in cached.items() if k!='attacks'})
                result['early_rejections'].append(row);completed[ekey]=row
                logstream.write(json.dumps(row)+'\n');logstream.flush()
                return row
            if key not in cache:
                p=LWE.Parameters(n=case['N'],q=ZZ(2)**case['q_est_log2'],Xs=ND.Ternary,
                                 Xe=ND.DiscreteGaussian(3.2),m=oo,tag=f'N{key[0]}_qbits{key[1]}')
                values={}
                for name,attack in attacks.items():
                    t=time.monotonic();answer=attack(p,red_cost_model=RC.MATZOV)
                    bits=str(log(answer['rop'],2).n());finite=math.isfinite(float(bits))
                    values[name]={'cost':{str(k):str(x) for k,x in answer.items()},'log2_rop':bits,
                                  'finite_estimate':finite,'target_pass':finite and bool(answer['rop']>=ZZ(2)**128),
                                  'wall_seconds':time.monotonic()-t}
                    print(case['branch'],name,bits,flush=True)
                    result['new_attack_calls']+=1
                    witness=rejection_witness(values)
                    if witness is not None:
                        rejected_cache[key]={'attacks':values,'origin':'computed_in_this_execution'}
                        row=dict(case,attacks=values,all_three_attacks_pass=False,rejection_witness=witness,
                                 estimate_provenance={'origin':'computed_in_this_execution'})
                        result['early_rejections'].append(row);completed[ekey]=row
                        logstream.write(json.dumps(row)+'\n');logstream.flush()
                        return row
                cache[key]={'attacks':values,'origin':'computed_in_this_execution'}
            else:result['reused_cases']+=1
            cached=cache[key];row=dict(case,attacks=cached['attacks'],
                estimate_provenance={k:x for k,x in cached.items() if k!='attacks'})
            row['all_three_attacks_pass']=all(x['target_pass'] for x in row['attacks'].values())
            result['cases'].append(row);completed[ekey]=row
            logstream.write(json.dumps(row)+'\n');logstream.flush()
            return row

        for filename in v.priorities:
            source=Path(filename).resolve();data=json.loads(source.read_text())
            backend=source.parent/'backend_crosscheck.json';checks=json.loads(backend.read_text())
            if not checks['all_pass']:raise ValueError('backend public checks incomplete')
            checked={str((source.parent/r['config']).resolve()) for r in checks['records'] if r['conditional_correctness']}
            result['priority_sources'].append({'path':str(source),'sha256':digest(source),'backend_sha256':digest(backend)})
            evaluated={}
            def check(row):
                identity=row['candidate_id']
                if identity in evaluated:return evaluated[identity]
                config=(source.parent/row['config']).resolve()
                if str(config) not in checked:raise ValueError('candidate is not backend checked')
                plan=json.loads(config.with_name(config.stem+'_plan.json').read_text())
                cert=json.loads(config.with_name(config.stem+'_certificate.json').read_text())
                if not cert['all_branches_pass'] or int(plan['preflight_memory_guard_bytes'])>8*2**30:
                    verdict={'pass':False,'reason':'certificate_or_memory'}
                else:
                    cases=plan_cases(plan);records=[]
                    for case in cases:
                        if exact(case) not in permitted:raise ValueError('case outside declared public union')
                        records.append(estimate(permitted[exact(case)]))
                        # A candidate needs every independent key family to
                        # pass. One failed family is already conclusive.
                        if not records[-1]['all_three_attacks_pass']:break
                    verdict={'pass':all(r['all_three_attacks_pass'] for r in records),
                             'reason':('actual_below_target_attack' if any(r.get('rejection_witness') for r in records)
                                       else 'three_actual_attack_estimates'),
                             'cases':[r['branch'] for r in records]}
                evaluated[identity]=verdict;return verdict
            decisions=ranked_select(data['candidates'],check)
            result['ranked_decisions'].append({'question_id':data['question']['id'],'source':str(source),'decisions':decisions})
            print('selection checked',data['question']['id'],[r['selected_candidate_id'] for r in decisions],flush=True)
    result['all_cases_pass']=not result['early_rejections'] and all(r['all_three_attacks_pass'] for r in result['cases'])
    result['unevaluated_exact_cases']=len(permitted)-len(completed)
    with out.open('x') as f:json.dump(result,f,indent=2);f.write('\n')


if __name__=='__main__':main()
