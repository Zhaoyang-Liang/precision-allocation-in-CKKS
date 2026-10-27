"""Experiment 08: finite, empirical recovery-boundary search at fixed scale.

Targets and mean are exact rational labels used to synthesize an integral unit.
Scale = 2**(28 + nominal_mean + growth_allowance + depth). This is an explicit
budget policy, not an assertion that measured numerator noise equals 2**28.
The public sufficient certificate is recorded separately and never decides wrap.
"""
import argparse,csv,hashlib,itertools,json,math,os,subprocess,sys,time
from fractions import Fraction as F
from functools import lru_cache
from pathlib import Path
CODE=Path(__file__).resolve().parent
sys.path[:0]=[str(CODE/'python_deps'),str(CODE/'public')]
from multipliers import design_profile
from profile_certificate import branch_certificate,phase
from profile_selection import contract_branch
from selector import balanced_widths,allocate_primes

if hasattr(sys,'set_int_max_str_digits'):sys.set_int_max_str_digits(0)

def dump(path,x):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with path.open('x') as f:json.dump(x,f,ensure_ascii=False,indent=2);f.write('\n')

def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()

def tables(path,rows):
    path=Path(path)
    keys=list(dict.fromkeys(k for row in rows for k in row))
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=keys);w.writeheader()
        for row in rows:w.writerow({k:(json.dumps(v,separators=(',',':')) if isinstance(v,(list,dict)) else v) for k,v in row.items()})

@lru_cache(None)
def unit(r,mean):
    if r==1:return dict(period=1,coefficients=['1'],inverse_coefficients=['1'],embedding_intervals=[dict(lower='1',upper='1')],actual_log2_weights_display=[0.0],coefficient_bits=1,target_bits=['20'],mean_target_bits='20',target_log2_weights=['0'],inverse_identity_pass=True)
    dummy=F(r*mean-20,r-1)
    u=design_profile([F(20)]+[dummy]*(r-1));u['requested_theta']=float(F(20-mean,r-1));return u

def tasks():
    out=[]
    for family,k in itertools.product(['grow','shrink'],[0,1,2,4]):
        for r,b in [(1,20)]+list(itertools.product([2,4],[10,0,-10,-20])):
            growth=2**k-1 if family=='grow' else 0
            out.append(dict(id=f'r{r}_b{b}_k{k}_{family}'.replace('-','m'),classes=r,nominal_mean_bits=b,depth=k,input_family=family,N=32768,messages=256,noise_budget_bits=28,growth_allowance_bits=growth,depth_allowance_bits=k,scale_bits=28+b+growth+k,Q_search_ceiling_bits=736,arithmetic_precision_bits=1024,formal_repeats=5))
    return out

def schedule(base,k):
    current=base;blocks=[];nominal=[base]
    for _ in range(k):
        removed=2*current-base
        # At small scales, defer rescale until a >=24-bit NTT limb can be removed.
        widths=balanced_widths(removed,60) if removed>=24 else []
        blocks.append(widths);current=2*current-sum(widths);nominal.append(current)
    return blocks,nominal

def settings(t,bottom):
    blocks,nominal=schedule(t['scale_bits'],t['depth'])
    widths=balanced_widths(bottom,60)+[b for block in reversed(blocks) for b in block]
    q=allocate_primes(t['N'],widths);p=allocate_primes(t['N'],[60,60],q)
    return dict(schema='ckks-zero-mean-v1',log_n=t['N'].bit_length()-1,base_precision_budget_bits=t['nominal_mean_bits'],baseline_numerator_noise_budget_bits=t['noise_budget_bits'],scale_bits=t['scale_bits'],depth=t['depth'],rescale_counts=list(map(len,blocks)),rescale_count=0,bottom_prime_count=len(balanced_widths(bottom,60)),effective_messages=t['messages'],arithmetic_precision_bits=1024,Q=list(q),P=list(p))

def public_check(t,s,u):
    mult={k:u[k] for k in ['period','coefficients','inverse_coefficients','embedding_intervals']}
    design=dict(groups=[0],slot_pattern=[] if t['classes']==1 else [0]+[-1]*(t['classes']-1),multiplier=mult)
    b=contract_branch('direct',design,t['N'],s['Q'],s['P'],s['rescale_counts'],s['scale_bits'])
    c=branch_certificate(b,1024,[20],t['depth'],F(2 if t['input_family']=='grow' else 1))
    result=dict(public_sufficient_certificate_pass=c['pass'],public_reasons=c['reasons'],certified_precision_bits=c['group_errors']['0']['bits_display'],final_range_ratio_log2=max(math.log2(F(x).numerator)-math.log2(F(x).denominator) for x in c['range_ratios_upper']))
    return result,c

def run_cell(t,binary,out,pilot=False):
    out=Path(out);out.mkdir(parents=True,exist_ok=False)
    u=unit(t['classes'],t['nominal_mean_bits']);dump(out/'unit.json',u);dump(out/'task.json',t)
    records=[];layer_records=[];trials=0
    blocks,_=schedule(t['scale_bits'],t['depth']);spent=sum(map(sum,blocks));ceiling=t['Q_search_ceiling_bits']-spent
    def probe(bottom,stage,repeat):
        nonlocal trials
        trials+=1;tag=f'p{trials:03d}_q{bottom}_{stage}_r{repeat}';d=out/tag;d.mkdir()
        s=settings(t,bottom);dump(d/'settings.json',s)
        cmd=[str(binary),'-settings',str(d/'settings.json'),'-unit',str(out/'unit.json'),'-input',t['input_family'],'-out',str(d/'raw')]
        start=time.monotonic()
        with (d/'stdout.log').open('x') as log:
            z=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
        if z.returncode:
            raise RuntimeError(f"execution error, not experimental failure: {d}; { (d/'stdout.log').read_text()[-1800:]}")
        result=json.loads((d/'raw/result.json').read_text());layers=result['layers'];last=layers[-1]
        recovered=result['last_recoverable_depth']==t['depth'];qbits=math.log2(math.prod(s['Q']));qpbits=math.log2(math.prod(s['Q']+s['P']))
        row=dict(task_id=t['id'],classes=t['classes'],nominal_mean_bits=t['nominal_mean_bits'],nominal_dummy_bits='' if t['classes']==1 else str(F(t['classes']*t['nominal_mean_bits']-20,t['classes']-1)),depth=t['depth'],input_family=t['input_family'],N=t['N'],messages=t['messages'],initial_scale_bits=t['scale_bits'],noise_budget_bits=t['noise_budget_bits'],growth_allowance_bits=t['growth_allowance_bits'],depth_allowance_bits=t['depth_allowance_bits'],actual_log2_weights=u['actual_log2_weights_display'],unit_coefficient_bits=u['coefficient_bits'],inverse_coefficient_bits=max(abs(int(x)).bit_length() for x in u['inverse_coefficients']),stage=stage,repeat=repeat,trial=trials,bottom_budget_bits=bottom,Q_bits=qbits,Q_count=len(s['Q']),QP_bits=qpbits,P_count=len(s['P']),Q=s['Q'],P=s['P'],rescale_counts=s['rescale_counts'],restoration_pass=recovered,target_20_bits_pass=recovered and last['target_20_bits_pass'],last_recoverable_depth=result['last_recoverable_depth'],first_failure_depth=result['first_failure_depth'],terminal_reason=result['terminal_reason'],actual_precision_bits=last['useful_precision_bits'],observed_depth=last['depth'],fresh_precision_bits=layers[0]['useful_precision_bits'],fresh_noise_coefficient_max=result['fresh_noise_coefficient_max'],dummy_magnitude_log2=last['max_dummy_magnitude_log2'],shadow_to_halfQ_log2=last['shadow_to_halfQ_log2'],node=result['host'],job_id=result['slurm_job_id'],array_task=result['slurm_array_task_id'],binary_sha256=result['binary_sha256'],diagnostic_wall_seconds=time.monotonic()-start,run_path=str(d),result_sha256=sha(d/'raw/result.json'))
        records.append(row)
        for l in layers:
            layer_records.append(dict(task_id=t['id'],trial=trials,stage=stage,repeat=repeat,bottom_budget_bits=bottom,depth=l['depth'],wrap=l['wrap'],target_20_bits_pass=l['target_20_bits_pass'],precision_bits=l['useful_precision_bits'],Q_bits=l['Q_bits'],Q_count=l['remaining_Q_primes'],scale_log2=l['scale_log2'],shadow_to_halfQ_log2=l['shadow_to_halfQ_log2'],dummy_magnitude_log2=l['max_dummy_magnitude_log2'],integer_congruence_pass=l['shadow_actual_congruence_pass']))
        tables(out/'runs.csv',records);tables(out/'layers.csv',layer_records)
        print(json.dumps({k:row[k] for k in ['task_id','trial','stage','bottom_budget_bits','restoration_pass','actual_precision_bits','observed_depth']},ensure_ascii=False),flush=True)
        return row
    status='not_started';chosen=None;formal=[];neighbor=[]
    if ceiling<24:
        status='chain_cost_above_registered_Q_ceiling'
    elif pilot:
        chosen=min(ceiling,80);formal=[probe(chosen,'pilot',1)];status='pilot_only'
    else:
        high=probe(ceiling,'search_cap',1)
        if not high['restoration_pass']:
            formal=[high]+[probe(ceiling,'cap_validation',i) for i in range(2,6)]
            status='no_recovery_at_registered_Q_ceiling'
        else:
            lo,hi=23,ceiling
            while hi-lo>1:
                mid=(lo+hi)//2;row=probe(mid,'search',1)
                if row['restoration_pass']:hi=mid
                else:lo=mid
            chosen=hi
            # At a stochastic edge, require five fresh successful encryptions.
            while chosen<=ceiling:
                formal=[probe(chosen,'candidate_validation',i) for i in range(1,6)]
                if all(x['restoration_pass'] for x in formal):break
                chosen+=1
            if chosen>ceiling:
                chosen=None;status='no_five_run_recovery_candidate'
            else:
                status='five_run_recovery_verified'
                if chosen>24:neighbor=[probe(chosen-1,'lower_neighbor',i) for i in range(1,6)]
                if neighbor and all(x['restoration_pass'] for x in neighbor):status='five_run_recovery_verified_lower_neighbor_also_passes'
                if chosen==24:status='five_run_recovery_verified_at_search_floor'
    summary=dict(task=t,status=status,selected_bottom_budget_bits=chosen,search_floor_bits=24,search_ceiling_bottom_bits=ceiling,search_Q_ceiling_bits=t['Q_search_ceiling_bits'],search_probes=trials,finite_search_only=True,selection_rule='Adaptive empirical bracket; new keys per probe; five fresh repeats at candidate and lower 1-bit neighbor. Not a global mathematical minimum.',formal_trials=[x['trial'] for x in formal],neighbor_trials=[x['trial'] for x in neighbor],formal_recovery_count=sum(x['restoration_pass'] for x in formal),formal_target20_count=sum(x['target_20_bits_pass'] for x in formal),formal_precision_min=min((float(x['actual_precision_bits']) for x in formal),default=None),formal_precision_max=max((float(x['actual_precision_bits']) for x in formal),default=None),Q_bits=formal[-1]['Q_bits'] if formal else None,QP_bits=formal[-1]['QP_bits'] if formal else None,source_sha256=sha(__file__),binary_sha256=sha(binary))
    if formal:
        s=settings(t,formal[-1]['bottom_budget_bits']);pc,cert=public_check(t,s,u);summary.update(pc);dump(out/'certificate.json',cert);dump(out/'selected_settings.json',s)
    dump(out/'summary.json',summary)
    return summary

def main():
    ap=argparse.ArgumentParser();sub=ap.add_subparsers(dest='command',required=True)
    sub.add_parser('register')
    run=sub.add_parser('run');run.add_argument('--task-index',type=int,required=True);run.add_argument('--binary',type=Path,required=True);run.add_argument('--out',type=Path,required=True);run.add_argument('--pilot',action='store_true')
    args=ap.parse_args()
    if args.command=='register':
        dump(CODE/'configurations/tasks.json',dict(schema='pa-zero-mean-design-v1',tasks=tasks(),nominal_target_bits=20,input_recipe='256 evenly spaced rational values in [1,2], or their exact reciprocals; identical plaintexts across methods; independently sampled keys and encryption noise.',schedule='Common numerator-noise budget 28 bits, plus depth and growing-input allowance; flat target scale with deferred rescale below the 24-bit limb family.',security='Record exact QP; independently run the same three RC.MATZOV attacks as experiment 07; security is not inferred from observed decryption.',failure_rule='Exact restored polynomial shadow wraps outside centered Q; target20 is separately observed. Bound failure is not decryption failure.',search='Registered Q <=736 bits; bottom width >=24. Adaptive empirical bracket, five-repeat validation and adjacent-point validation; not a global optimum.'))
        for r,b in [(1,20)]+list(itertools.product([2,4],[10,0,-10,-20])):dump(CODE/f'configurations/unit_r{r}_b{b}.json',unit(r,b))
        print(len(tasks()),'registered task cells')
    else:run_cell(tasks()[args.task_index],args.binary.resolve(),args.out.resolve(),args.pilot)
if __name__=='__main__':main()
