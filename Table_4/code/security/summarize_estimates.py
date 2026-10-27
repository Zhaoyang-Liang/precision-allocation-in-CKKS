import sys
import os
#!/usr/bin/env python3
"""Collect completed runs without silently treating failed/infinite estimates as security."""
import json
import math
from pathlib import Path

ROOT = Path(os.environ.get("CKKS_SECURITY_WORK", str(Path(__file__).resolve().parents[2] / "result/recomputed_security"))).resolve()
ROOT.mkdir(parents=True, exist_ok=True)
if not (ROOT / "inputs.json").exists():
    manifest_copy = json.loads((Path(__file__).resolve().parents[2] / "result/security/inputs.json").read_text())
    if os.environ.get("LATTICE_ESTIMATOR"):
        manifest_copy["estimator_path"] = os.environ["LATTICE_ESTIMATOR"]
    (ROOT / "inputs.json").write_text(json.dumps(manifest_copy, indent=2) + "\n")
manifest=json.loads((ROOT/'inputs.json').read_text())
results={}
pending=[]
errors=[]
for spec in manifest['instances']:
    name=spec['id']
    records={}
    files=[ROOT/(name+'.json')]
    if spec['secret_weight']:
        files.append(ROOT/(name+'_sparse.json'))
    for file in files:
        if not file.exists():
            pending.append(file.name)
            continue
        d=json.loads(file.read_text())
        if not d.get('complete'):
            pending.append(file.name)
        for attack,v in d['attacks'].items():
            if v['status']!='ok':
                errors.append((name,attack,v.get('error')))
            records[attack]=v
    finite=[(v['bits'],attack) for attack,v in records.items()
            if v['status']=='ok' and math.isfinite(v['bits'])]
    best=min(finite) if finite else (None,None)
    results[name]={'minimum_finite_bits':best[0],'limiting_attack':best[1],
                   'attack_bits':{k:(v['bits'] if math.isfinite(v.get('bits',float('inf'))) else None)
                                  for k,v in records.items()},
                   'search_limit_beta':1754}
columns={}
for case in manifest['columns']:
    finite=[(results[key]['minimum_finite_bits'],role,key)
            for role,key in manifest['mapping'][case].items()
            if results[key]['minimum_finite_bits'] is not None]
    best=min(finite) if finite else (None,None,None)
    columns[case]={'bits':best[0],'limiting_role':best[1],'limiting_instance':best[2],
                   'limiting_attack':results[best[2]]['limiting_attack'] if best[2] else None}
summary={'complete':not pending and not errors,'pending':pending,'errors':errors,
         'columns':columns,'instances':results}
(ROOT/'summary.json').write_text(json.dumps(summary,indent=2,allow_nan=False)+'\n')
for case,c in columns.items():
    print(case,c)
print('Pending:',pending)
print('Errors:',errors)
if not summary['complete']:
    raise SystemExit(1)
cells=[f'\\multicolumn{{2}}{{{"c" if i==5 else "c|"}}}{{{columns[case]["bits"]:.2f}}}'
       for i,case in enumerate(manifest['columns'])]
(ROOT/'table-row.tex').write_text('\\hline\nRLWE est. (bits) & '+' & '.join(cells)+' \\\\\n')
lines=[
    'Classical RLWE security estimates for round-18 bootstrapping configurations',
    '',
    'Estimator: '+manifest['estimator_path'],
    'Tracked source commit: '+manifest['estimator_commit'],
    'Summary runtime: '+sys.executable,
    'The tracked estimator source was not modified.',
    'Noise: DiscreteGaussian(3.2), matching Lattigo v6.2.0 rlwe.DefaultNoise.',
    'Dimension: full RLWE polynomial degree, without subtracting one.',
    'Modulus: 2^ceil(log2 of the largest QP exposed under each receiving secret).',
    'Samples: unbounded. Reduction work-factor model: RC.MATZOV (classical).',
    'Dense secrets: ND.Ternary. Fixed-total-weight secrets: balanced ND.SparseTernary(h/2,h/2,n) proxy.',
    'The implementation uses independent signs, so the balanced proxy is an explicit modeling approximation.',
    'Every instance: primal-uSVP, primal-BDD, and MATZOV dual-hybrid.',
    'Fixed-weight instances additionally: primal hybrid, primal MITM hybrid, sparse dual hybrid, sparse dual MITM.',
    'Default beta search cap: 1754. An infinite result means no finite attack was returned within the model/search, not infinite security.',
    'The table reports the minimum finite attack estimate over the top, leaf/main, and encapsulation-secret instances.',
    'The estimates do not independently prove circular/KDM security of published related-key material.',
    '',
    'Public-modulus audit:',
    'Fiber main secret: full Q_bts times all P primes (rotation, relinearization, and lift keys).',
    'Fiber top secret: Q_out times all P primes (return key); no larger top-ring key is published.',
    'Fiber ephemeral secret: q_0 times all P primes (SSE entry key).',
    '17->13 top secret: q_0*q_out*TopP; ephemeral: q_0, since the entry key uses no P.',
    'Direct13 main secret: Q_bts*MainP; ephemeral: q_0*SmallP from the auxiliary-P entry key.',
    'PA unit multiplication is a public invertible representation change and is not used to shrink the security noise parameter.',
    '',
    'Table order and limiting estimates:',
]
for case,c in columns.items():
    lines.append(f'{case}: {c["bits"]:.8f} bits; {c["limiting_role"]}; {c["limiting_attack"]}; {c["limiting_instance"]}')
lines.extend(['','All estimated instances:'])
for spec in manifest['instances']:
    name=spec['id']
    lines.append(f'{name}: exact log2 QP={spec["log2_actual_q"]:.12f}; {json.dumps(results[name])}')
(ROOT/'security-report.txt').write_text('\n'.join(lines)+'\n')
