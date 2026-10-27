"""Rebuild paper data from retained observations; no HE runs."""
from pathlib import Path
from collections import defaultdict
from fractions import Fraction
import argparse,csv,json,math,statistics,sys
ROOT=Path(__file__).resolve().parents[1]
ART=ROOT.name
DATA=ROOT/'result/source_data'
p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--out',type=Path,default=ROOT/'result/reproduced')
a=p.parse_args(); OUT=a.out.resolve();OUT.mkdir(parents=True,exist_ok=True)
def read(name):
 with (DATA/name).open(encoding='utf-8-sig',newline='') as f:return list(csv.DictReader(f))
def write(name,rows):
 assert rows
 with (OUT/name).open('w',newline='') as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
def num(v):
 x=Fraction(v);return math.log2(abs(x.numerator))-math.log2(x.denominator)
def selected(rows,scenes,priority,depth):
 rows=[r for r in rows if r['scene'] in scenes and priority in r['priorities'].split('|') and int(r['depth'])==depth]
 assert len({(r['task_id'],r['classes']) for r in rows})==len(rows)
 assert all(r['all_five_runs_pass']=='True' and r['repeat_count']=='5' for r in rows)
 return rows
if ART=='Figure_1':
 raw=read('runs.csv');assert len(raw)==2032
 g=defaultdict(list)
 for r in raw:g[(int(r['classes']),r['input_family'],int(r['theta']))].append(int(r['last_recoverable_depth']))
 rows=[dict(classes=c,input_family=f,theta=t,median_depth=statistics.median(v),min_depth=min(v),max_depth=max(v),repeats=len(v)) for (c,f,t),v in sorted(g.items())]
 write('paper_data.csv',rows)
elif ART=='Figure_2':
 rows=selected(read('summary.csv'),{'small'},'min_N_then_Q',6)
 assert len(rows)==24
 write('paper_data.csv',rows)
elif ART=='Figure_3':
 curve=[r for r in read('theta_Q.csv') if int(r['depth'])==4 and r['queried_for_layout_theta']=='True']
 write('paper_data_panel_a.csv',curve)
 rows=selected(read('summary.csv'),{'capacity','boundary'},'online_word_proxy',4)
 base={(r['messages'],r['input_family']):float(r['median_online_ms']) for r in rows if r['classes']=='1'}
 for r in rows:r['speedup_vs_CKKS']=base[r['messages'],r['input_family']]/float(r['median_online_ms'])
 write('paper_data_panel_b.csv',rows)
elif ART=='Figure_4':
 rows=[r for r in read('summary.csv') if int(r['depth']) in (0,4)]
 assert len(rows)==36
 write('paper_data.csv',rows)
elif ART=='Table_2':
 rows=[r for r in selected(read('summary.csv'),{'small'},'min_N_then_Q',6) if r['messages']=='256' and r['target_bits']=='224' and r['input_family']=='grow']
 assert len(rows)==3
 table=[]
 for r in sorted(rows,key=lambda r:int(r['classes'])):
  table.append(dict(method='CKKS' if r['classes']=='1' else 'classes_'+r['classes'],N=int(r['N']),log2_Q=float(r['Q_bits']),online_seconds=float(r['median_online_ms'])/1000,worst_precision_bits=float(r['worst_actual_precision_bits']),security_bits=float(r['security_min_bits']),candidate_id=r['candidate_id']))
 write('paper_data.csv',table);write('selected_configurations.csv',rows)
elif ART in ('Table_4','Table_5'):
 R=ROOT/'result'; prov=json.loads((R/'table_parameters.json').read_text());saved=json.loads((R/'summary.json').read_text());sec=json.loads((R/'security/summary.json').read_text())
 order=['leaf17-15','leaf17-13','direct16','leaf16-15','leaf16-14','direct13']; rows=[]
 for case in order:
  v=prov['parameters'][case];s=saved[case]['summary'];tr=saved[case]['trials'];runs=[json.loads((R/'raw_runs'/('run-'+job)/'result.json').read_text()) for job in prov['source_jobs'][case]]
  assert len({r['MainQBits'] for r in runs})==len({r['MainQPBits'] for r in runs})==1
  if ART=='Table_4':
   rows.append(dict(case=case,log2_N=v['N'],log2_n=v['n'],useful_branches=1,messages=v['msg'],L_in=v['Lin'],L_out=tr[0]['output']['Level'],input_scale_bits=v['inScale'],EvalMod_scale_bits=v['emScale'],output_scale_bits=v['outScale'],log2_Q_in=v['qin'],log2_Q_bts=runs[0]['MainQBits'],log2_Q_out=v['qout'],log2_PQ_bts=runs[0]['MainQPBits'],security_bits=sec['columns'][case]['bits']))
  else:
   def avg(key):return statistics.mean(t['stages'][key] for t in tr) if key in tr[0]['stages'] else ''
   fused=case in ('leaf17-13','direct13')
   rows.append(dict(case=case,split_seconds=statistics.mean(t['entry'] for t in tr),StC_seconds='' if fused else avg('StCSeconds'),ModRaise_seconds='' if fused else statistics.mean(t['stages']['SSESeconds']+t['stages']['LiftTraceSeconds'] for t in tr),CtS_seconds='' if fused else avg('CtSSeconds'),fused_seconds=avg('ReadoutSeconds') if fused else '',EvalMod_seconds=avg('EvalModSeconds'),merge_seconds='' if case=='direct13' else statistics.mean(t['return_time'] for t in tr),serial_seconds=s['serial_mean'],parallel_seconds=s['parallel_mean'],minimum_precision_bits=s['min_bits'],keygen_seconds=s['keygen_mean'],server_key_GiB=s['key_GiB'],independent_key_sets=s['keys'],trials=s['trials']))
 write('paper_data.csv',rows)
elif ART=='Table_6':
 rows=[r for r in read('error_comparison.csv') if r['method']=='allocated_joint']
 cert=json.loads((ROOT/'code/configurations/slot0_certificate.json').read_text())['branches'][0]
 weights=[num(w['float_exact']) for w in cert['encoding']['weights']]
 table=[]
 def add(label,kind=None,group=None,normalize=False,observed=None,bound=None,source=None):
  if kind:
   rr=[r for r in rows if r['kind']==kind and (group is None or int(r['group'])==group)]
   assert rr
   observed=max(float(r['observed_log2_magnitude'])-(weights[int(r['group'])] if normalize else 0) for r in rr)
   bound=max(float(r['backend_bound_log2'])-(weights[int(r['group'])] if normalize else 0) for r in rr)
  table.append(dict(quantity=label,observed_log2=observed,upper_bound_log2=bound,gap_bits=bound-observed,source=source or kind))
 add('encoding_error','fresh_encoding_error');add('encryption_noise','fresh_decryption_noise')
 for i in range(1,5):add(f'kappa_{i}',f'layer{i}_kappa')
 for i in range(1,5):add(f'rescale_numerator_{i}',f'layer{i}_rescale_numerator')
 amplitude=16*math.log2(7/8)
 add('maximum_output_message',observed=amplitude,bound=amplitude,source='Exact maximum input 7/8 after four squarings')
 add('eta_0','fresh_restored_error',normalize=True)
 for i in range(1,4):add(f'eta_{i}',f'layer{i}_normalized_residual')
 for g in range(4):add(f'eta_4_group_{g}','layer4_normalized_residual',group=g)
 add('eta_4_all','layer4_normalized_residual')
 for g in range(4):add(f'output_error_group_{g}','final_restored_error',group=g)
 coeff=next(r for r in read('coefficient_summary.csv') if r['method']=='allocated_joint' and r['file'].endswith('layer4_M.coefficients.jsonl.gz'))
 obs=float(coeff['maximum_log2'])-num(cert['output_scale_exact'])
 # The all-slot input-uniform bound follows the paper's triangle inequality.
 maxerror=max(Fraction(x) for x in cert['final_logical_error_upper'])
 ub=num(Fraction(7,8)**16+maxerror)
 add('normalized_coefficient_maximum',observed=obs,bound=ub,source='coefficient_summary.csv and input-uniform amplitude plus final error bound')
 write('paper_data.csv',table)
else:raise SystemExit('Unsupported artifact directory: '+ART)
print(ART+': regenerated data in '+str(OUT))
