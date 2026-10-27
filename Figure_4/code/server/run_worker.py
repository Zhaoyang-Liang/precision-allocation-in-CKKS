import concurrent.futures,os,subprocess,sys
from pathlib import Path
root=Path(__file__).resolve().parents[2]
worker=int(os.environ['SLURM_ARRAY_TASK_ID']);workers=12;cpus=int(os.environ['SLURM_CPUS_PER_TASK'])
out=root/'results'/('formal_'+os.environ['SLURM_ARRAY_JOB_ID']);out.mkdir(exist_ok=True,parents=True)
def run(index):
 log=out/f'cell_{index}.driver.log'
 cmd=[sys.executable,str(root/'code/zero_mean_experiment.py'),'run','--task-index',str(index),'--binary',str(root/'build/zeromean'),'--out',str(out/f'cell_{index}')]
 with log.open('x') as f:r=subprocess.run(cmd,stdout=f,stderr=subprocess.STDOUT)
 return index,r.returncode
with concurrent.futures.ThreadPoolExecutor(max_workers=cpus) as pool:
 results=list(pool.map(run,range(worker,72,workers)))
print(results,flush=True)
if any(code for _,code in results):raise SystemExit(1)
