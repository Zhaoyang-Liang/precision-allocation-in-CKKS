import os,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2]
worker=int(os.environ['SLURM_ARRAY_TASK_ID']);out=root/'security_results';out.mkdir(exist_ok=True)
plans=sorted((root/'exports/formal_149026/security_plans').glob('plan_*.json'))
if not plans:raise RuntimeError('no security plans')
runtime=Path.home()/'projects/tuple8-study-20261017-a/tools'
for p in plans[worker::6]:
 with (out/(p.stem+'.log')).open('x') as log:
  cmd=[str(runtime/'sage/bin/sage'),'-python',str(root/'code/security/estimate_cases.py'),'--plan',str(p),'--estimator',str(runtime/'lattice-estimator'),'--out',str(out/(p.stem+'.json'))]
  r=subprocess.run(cmd,stdout=log,stderr=subprocess.STDOUT)
 if r.returncode:raise RuntimeError('security estimator failed: '+str(p))
 print('completed',p.name,flush=True)
