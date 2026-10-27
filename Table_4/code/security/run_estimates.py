#!/usr/bin/env python3
"""Reproduce classical estimates for the actual round-18 bootstrap parameters."""
import argparse
import concurrent.futures
import json
import math
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


def worker(instance_id):
    manifest = json.loads((ROOT / 'inputs.json').read_text())
    spec = next(x for x in manifest['instances'] if x['id'] == instance_id)
    sys.path.insert(0, manifest['estimator_path'])
    from sage.all import ZZ, log, oo
    from estimator import LWE, ND, RC
    h, n = spec['secret_weight'], spec['dimension']
    secret = ND.Ternary if not h else ND.SparseTernary(h // 2, h // 2, n=n)
    params = LWE.Parameters(n=n, q=ZZ(2)**spec['log2_estimator_q'],
                            Xs=secret, Xe=ND.DiscreteGaussian(spec['sigma']),
                            m=oo, tag=instance_id)
    result = {'instance': spec, 'python': sys.executable,
              'parameters': str(params), 'attacks': {}}
    out = ROOT / (instance_id + '.json')
    attacks = [('primal_usvp', LWE.primal_usvp),
               ('primal_bdd', LWE.primal_bdd),
               ('dual_hybrid', LWE.dual_hybrid)]
    print(params, flush=True)
    for name, attack in attacks:
        started = time.monotonic()
        print('START', name, flush=True)
        try:
            cost = attack(params, red_cost_model=RC.MATZOV)
            bits = float(log(cost['rop'], 2))
            record = {'status': 'ok', 'bits': bits,
                      'cost': {str(k): str(v) for k, v in cost.items()},
                      'display': repr(cost)}
            print('DONE', name, bits, repr(cost), flush=True)
        except Exception as exc:
            record = {'status': 'error', 'error': repr(exc),
                      'traceback': traceback.format_exc()}
            print('ERROR', name, repr(exc), flush=True)
        record['seconds'] = time.monotonic() - started
        result['attacks'][name] = record
        result['complete'] = len(result['attacks']) == len(attacks)
        good = [v['bits'] for v in result['attacks'].values() if v['status'] == 'ok']
        result['minimum_bits'] = min(good) if good else None
        temp = out.with_suffix('.tmp')
        temp.write_text(json.dumps(result, indent=2) + '\n')
        temp.replace(out)
    return int(any(v['status'] != 'ok' for v in result['attacks'].values()))


def launch(spec):
    name = spec['id']
    with (ROOT / (name + '.log')).open('w') as log_file:
        cmd = [sys.executable, str(Path(__file__).resolve()),
               '--worker', name]
        print('START INSTANCE', name, flush=True)
        proc = subprocess.run(cmd, stdout=log_file, stderr=subprocess.STDOUT,
                              env={**os.environ, 'OMP_NUM_THREADS': '1',
                                   'OPENBLAS_NUM_THREADS': '1'})
    print('FINISHED INSTANCE', name, 'exit', proc.returncode, flush=True)
    return name, proc.returncode


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--worker')
    parser.add_argument('--jobs', type=int, default=3)
    args = parser.parse_args()
    if args.worker:
        sys.exit(worker(args.worker))
    manifest = json.loads((ROOT / 'inputs.json').read_text())
    specs = manifest['instances']
    # Obtain the limiting main-ring estimates first; compute every top/ephemeral instance too.
    specs.sort(key=lambda x: (not any(r['role'] == 'main' for r in x['roles']),
                              x['dimension']))
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as executor:
        outcomes = list(executor.map(launch, specs))
    (ROOT / 'run-status.json').write_text(json.dumps(outcomes, indent=2) + '\n')
    sys.exit(int(any(code for _, code in outcomes)))
