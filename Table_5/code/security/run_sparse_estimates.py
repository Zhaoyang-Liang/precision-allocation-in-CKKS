#!/usr/bin/env python3
"""Additional hybrid attacks that explicitly exploit fixed-weight secrets."""
import argparse
import concurrent.futures
import fcntl
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

ROOT = Path(os.environ.get("CKKS_SECURITY_WORK", str(Path(__file__).resolve().parents[2] / "result/recomputed_security"))).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
if not (ROOT / "inputs.json").exists():
    manifest_copy = json.loads((Path(__file__).resolve().parents[2] / "result/security/inputs.json").read_text())
    if os.environ.get("LATTICE_ESTIMATOR"):
        manifest_copy["estimator_path"] = os.environ["LATTICE_ESTIMATOR"]
    (ROOT / "inputs.json").write_text(json.dumps(manifest_copy, indent=2) + "\n")


def worker(name):
    lock_file=(ROOT/(name+'_sparse.lock')).open('w')
    fcntl.flock(lock_file,fcntl.LOCK_EX)
    saved=ROOT/(name+'_sparse.json')
    if saved.exists():
        previous=json.loads(saved.read_text())
        if previous.get('complete') and all(v['status']=='ok' for v in previous['attacks'].values()):
            print('REUSE COMPLETE',name,flush=True)
            return 0
    manifest = json.loads((ROOT / 'inputs.json').read_text())
    spec = next(x for x in manifest['instances'] if x['id'] == name)
    sys.path.insert(0, manifest['estimator_path'])
    from sage.all import ZZ, log, oo
    from estimator import LWE, ND, RC
    from estimator.lwe_dual import dual_hybrid
    h, n = spec['secret_weight'], spec['dimension']
    params = LWE.Parameters(n=n, q=ZZ(2)**spec['log2_estimator_q'],
                            Xs=ND.SparseTernary(h//2, h//2, n=n),
                            Xe=ND.DiscreteGaussian(spec['sigma']), m=oo, tag=name)
    attacks = [
        ('primal_hybrid', lambda: LWE.primal_hybrid(params, mitm=False, babai=False, red_cost_model=RC.MATZOV)),
        ('primal_mitm_hybrid', lambda: LWE.primal_hybrid(params, mitm=True, babai=True, red_cost_model=RC.MATZOV)),
        ('dual_sparse_hybrid', lambda: dual_hybrid(params, red_cost_model=RC.MATZOV)),
        ('dual_sparse_mitm', lambda: dual_hybrid(params, red_cost_model=RC.MATZOV, mitm_optimization='analytical')),
    ]
    result = {'instance': spec, 'parameters': str(params), 'attacks': {}}
    out = ROOT / (name + '_sparse.json')
    print(params, flush=True)
    for attack, function in attacks:
        start = time.monotonic()
        print('START', attack, flush=True)
        try:
            cost = function()
            bits = float(log(cost['rop'],2))
            record = {'status':'ok','bits':bits,'cost':{str(k):str(v) for k,v in cost.items()},'display':repr(cost)}
            print('DONE', attack, bits, repr(cost), flush=True)
        except Exception as exc:
            record = {'status':'error','error':repr(exc),'traceback':traceback.format_exc()}
            print('ERROR', attack, repr(exc), flush=True)
        record['seconds'] = time.monotonic()-start
        result['attacks'][attack] = record
        result['complete'] = len(result['attacks'])==len(attacks)
        good = [v['bits'] for v in result['attacks'].values() if v['status']=='ok']
        result['minimum_bits'] = min(good) if good else None
        tmp = out.with_suffix('.tmp')
        tmp.write_text(json.dumps(result,indent=2)+'\n')
        tmp.replace(out)
    return int(any(v['status']!='ok' for v in result['attacks'].values()))


def launch(spec):
    name=spec['id']
    print('START SPARSE INSTANCE',name,flush=True)
    with (ROOT/(name+'_sparse.log')).open('w') as log_file:
        proc=subprocess.run([sys.executable,str(Path(__file__).resolve()),'--worker',name],
                            stdout=log_file,stderr=subprocess.STDOUT,
                            env={**os.environ,'OMP_NUM_THREADS':'1','OPENBLAS_NUM_THREADS':'1'})
    print('FINISHED SPARSE INSTANCE',name,'exit',proc.returncode,flush=True)
    return name,proc.returncode


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--worker')
    parser.add_argument('--jobs',type=int,default=2)
    args=parser.parse_args()
    if args.worker:
        sys.exit(worker(args.worker))
    manifest=json.loads((ROOT/'inputs.json').read_text())
    specs=[x for x in manifest['instances'] if x['secret_weight']]
    specs.sort(key=lambda x:(x['secret_weight'],x['dimension']))
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        outcomes=list(executor.map(launch,specs))
    (ROOT/'sparse-run-status.json').write_text(json.dumps(outcomes,indent=2)+'\n')
    sys.exit(int(any(code for _,code in outcomes)))
