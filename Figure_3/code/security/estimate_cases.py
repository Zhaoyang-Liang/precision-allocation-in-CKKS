#!/usr/bin/env python3
"""Run with Sage's Python, never with an emulated/mocked estimator.

Example:
  sage -python estimate_cases.py --plan plan.json --out security.json

Read-only use of the specified estimator repository. No HE, keys or server use.
All three attacks must complete; an exception is a failure, never a pass.
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


def ceil_log2_integer(n):
    if n <= 0:
        raise ValueError("positive integer required")
    return (n-1).bit_length()


def plan_cases(plan):
    result = []
    for branch in plan["branches"]:
        p = branch["parameters"]
        n = int(p["n"])
        q = list(map(int, p["Q"]))
        aux = list(map(int, p["P"]))
        if n < 16 or n & (n-1) or len(set(q+aux)) != len(q+aux):
            raise ValueError("invalid dimension or overlapping moduli")
        qp = math.prod(q+aux)
        if str(qp) != p["qp_exact"]:
            raise ValueError("plan modulus mismatch")
        result.append({"branch": branch["id"], "N": n, "Q":list(map(str,q)),
                       "P":list(map(str,aux)), "qp_exact":str(qp),
                       "q_est_log2":ceil_log2_integer(qp)})
    return result


def reusable_estimates(paths, commit, target):
    """Reuse only IDENTICAL estimator inputs, never interpolate security.

    Exact Q/P still appear in each output case. The estimator receives N and
    2**ceil(log2(QP)), so different exact primes can legitimately hit the same
    input. Original files and their hashes remain part of the evidence chain.
    """
    cache={};provenance=[]
    expected={'schema':'ckks-new-security-v1','estimator_commit':commit,
              'estimator_tracked_dirty':[],'model':'RC.MATZOV',
              'secret':'uniform_ternary','error_sigma':'3.2',
              'actual_sampler_abs_bound':'19.2','samples':'infinity','target_bits':target}
    for filename in paths:
        path=Path(filename).resolve();raw=path.read_bytes();data=json.loads(raw)
        if any(data.get(k)!=v for k,v in expected.items()):
            raise ValueError('reused security model/version mismatch: '+str(path))
        if len(data.get('wrapper_sha256',''))!=64:raise ValueError('missing wrapper provenance')
        digest=hashlib.sha256(raw).hexdigest()
        provenance.append({'path':str(path),'sha256':digest})
        for row in data['cases']:
            if int(row['qp_exact'])!=math.prod(map(int,row['Q']+row['P'])):
                raise ValueError('reused exact modulus mismatch')
            if row['q_est_log2']!=ceil_log2_integer(int(row['qp_exact'])):
                raise ValueError('reused estimator input mismatch')
            raw_attacks=row['attacks'];attacks=deepcopy(raw_attacks)
            if set(attacks)!={'primal_usvp','primal_bdd','dual_hybrid'}:
                raise ValueError('reused incomplete attacks')
            for attack in attacks.values():
                bits=float(attack['log2_rop'])
                if math.isnan(bits):raise ValueError('reused NaN work factor')
                if math.isfinite(bits) and bool(attack['target_pass'])!=(bits>=target):
                    raise ValueError('reused inconsistent work factor')
                if 'rop' not in attack['cost']:raise ValueError('reused raw cost missing')
                if not math.isfinite(bits):
                    attack['target_pass']=False
                    attack['finite_estimate']=False
                    attack['acceptance_note']='Nonfinite estimate retained but not accepted as a finite security work factor.'
            if row['all_three_attacks_pass']!=all(a['target_pass'] for a in raw_attacks.values()):
                raise ValueError('reused summary mismatch')
            key=(row['N'],row['q_est_log2'])
            if key in cache and any(abs(float(cache[key]['attacks'][k]['log2_rop'])-
                    float(attacks[k]['log2_rop']))>1e-8 for k in attacks):
                raise ValueError('conflicting identical-input estimates')
            cache[key]={'attacks':attacks,'origin_file_sha256':digest,
                        'origin_branch':row['branch']}
    return cache,provenance


def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--plan",required=True)
    ap.add_argument("--out",required=True)
    ap.add_argument("--estimator",default="/Users/mac/opt/lattice-estimator")
    ap.add_argument("--target-bits",type=int,default=128)
    ap.add_argument("--reuse",action='append',default=[],help='prior real results with identical model/version/inputs')
    args=ap.parse_args()
    output=Path(args.out)
    if output.exists():raise FileExistsError(output)
    wrapper_raw=Path(__file__).read_bytes()
    wrapper_copy=output.with_suffix('.wrapper.py')
    with wrapper_copy.open('xb') as f:f.write(wrapper_raw)
    raw=Path(args.plan).read_bytes()
    plan=json.loads(raw)
    cases=plan_cases(plan)
    repository=Path(args.estimator).resolve()
    commit=subprocess.check_output(["git","-C",str(repository),"rev-parse","HEAD"],text=True).strip()
    dirty=subprocess.check_output(["git","-C",str(repository),"diff","--name-only","HEAD"],text=True).splitlines()
    if dirty:raise RuntimeError("tracked estimator files modified; audit before estimating")
    sys.path.insert(0,str(repository))
    # Import here so pure schema tests can run without Sage. No fallback values.
    from sage.all import ZZ, oo, log
    from estimator import LWE, ND, RC
    attacks={"primal_usvp":LWE.primal_usvp,"primal_bdd":LWE.primal_bdd,"dual_hybrid":LWE.dual_hybrid}
    cache,provenance=reusable_estimates(args.reuse,commit,args.target_bits)
    result={"schema":"ckks-new-security-v1","plan_sha256":hashlib.sha256(raw).hexdigest(),
            "estimator_commit":commit,"estimator_tracked_dirty":dirty,
            "wrapper_sha256":hashlib.sha256(wrapper_raw).hexdigest(),
            "wrapper_source_file":str(wrapper_copy.resolve()),
            "model":"RC.MATZOV", "secret":"uniform_ternary", "error_sigma":"3.2",
            "actual_sampler_abs_bound":"19.2", "samples":"infinity",
            "target_bits":args.target_bits,"HE_executions":0,"cases":[],
            "reported_log_precision":"Sage default numerical precision; estimator costs are numerical estimates, not 128-bit arithmetic certificates",
            "reused_result_files":provenance,"new_attack_calls":0,"reused_cases":0}
    for case in cases:
        key=(case["N"],case["q_est_log2"])
        if key not in cache:
            params=LWE.Parameters(n=case["N"],q=ZZ(2)**case["q_est_log2"],Xs=ND.Ternary,
                                  Xe=ND.DiscreteGaussian(3.2),m=oo,tag=f"N{key[0]}_qbits{key[1]}")
            estimates={}
            for name,attack in attacks.items():
                start=time.monotonic()
                answer=attack(params,red_cost_model=RC.MATZOV)
                bits=str(log(answer["rop"],2).n())
                finite=math.isfinite(float(bits))
                estimates[name]={"cost":{str(k):str(v) for k,v in answer.items()},
                                 # The estimator may return a 53-bit real.
                                 # Asking that value for 128-bit accuracy raises
                                 # in Sage and would not add information anyway.
                                 "log2_rop":bits,"finite_estimate":finite,
                                 "target_pass":finite and bool(answer["rop"]>=ZZ(2)**args.target_bits),
                                 "wall_seconds":time.monotonic()-start}
                print(case["branch"],name,estimates[name]["log2_rop"],flush=True)
            cache[key]={'attacks':estimates,'origin':'computed_in_this_execution'}
            result['new_attack_calls']+=3
        else:
            result['reused_cases']+=1
        cached=cache[key]
        row=dict(case,attacks=cached['attacks'],estimate_provenance={k:v for k,v in cached.items() if k!='attacks'})
        row["all_three_attacks_pass"]=all(x["target_pass"] for x in cached['attacks'].values())
        result["cases"].append(row)
    result["all_cases_pass"]=all(x["all_three_attacks_pass"] for x in result["cases"])
    with output.open("x",encoding="utf-8") as f:
        json.dump(result,f,indent=2);f.write("\n")


if __name__=="__main__":main()
