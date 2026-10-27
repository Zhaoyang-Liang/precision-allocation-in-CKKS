"""Export only compact CSV, public settings and certificates; no secret data."""
import argparse,csv,json,math,shutil
from pathlib import Path
from zero_mean_experiment import tables,dump,unit

def export(source,out,expected=72):
 source=Path(source);out=Path(out);out.mkdir(exist_ok=False,parents=True)
 cells=sorted(source.glob('cell_*/summary.json'),key=lambda p:int(p.parent.name.split('_')[-1]))
 if len(cells)!=expected:raise ValueError(f'{len(cells)} completed cells; expected {expected}')
 runs=[];layers=[];summaries=[];security=[];units=[];configs=out/'selected_public_configs';configs.mkdir()
 for f in cells:
  s=json.loads(f.read_text());t=s['task'];records=list(csv.DictReader((f.parent/'runs.csv').open()))
  chosen=[r for r in records if int(r['trial']) in s['formal_trials']]
  neighbor=[r for r in records if int(r['trial']) in s['neighbor_trials']]
  row=dict(task_id=t['id'],classes=t['classes'],nominal_mean_bits=t['nominal_mean_bits'],nominal_dummy_bits='' if t['classes']==1 else str(__import__('fractions').Fraction(t['classes']*t['nominal_mean_bits']-20,t['classes']-1)),depth=t['depth'],input_family=t['input_family'],N=t['N'],messages=t['messages'],initial_scale_bits=t['scale_bits'],status=s['status'],selected_bottom_budget_bits=s['selected_bottom_budget_bits'],Q_bits=s['Q_bits'],QP_bits=s['QP_bits'],formal_repeats=len(chosen),formal_recovery_count=s['formal_recovery_count'],formal_target20_count=s['formal_target20_count'],actual_precision_min=s['formal_precision_min'],actual_precision_max=s['formal_precision_max'],lower_neighbor_recovery_count=sum(r['restoration_pass']=='True' for r in neighbor),lower_neighbor_target20_count=sum(r['target_20_bits_pass']=='True' for r in neighbor),lower_neighbor_repeats=len(neighbor),public_certificate_pass=s.get('public_sufficient_certificate_pass'),certified_precision_bits=s.get('certified_precision_bits'),public_reasons=s.get('public_reasons',[]),search_probes=s['search_probes'],Q_search_ceiling_bits=t['Q_search_ceiling_bits'],candidate_verified=bool(s['selected_bottom_budget_bits'] is not None and s['formal_recovery_count']==5),final20_verified=bool(s['selected_bottom_budget_bits'] is not None and s['formal_target20_count']==5))
  if chosen:
   for k in ['Q_count','P_count','rescale_counts','actual_log2_weights','unit_coefficient_bits','inverse_coefficient_bits']:row[k]=chosen[0][k]
  summaries.append(row)
  for r in records:r['selected_validation']=int(r['trial']) in s['formal_trials'];r['lower_neighbor_validation']=int(r['trial']) in s['neighbor_trials'];r['fresh_useful_implied_base_precision_bits']=float(r['fresh_precision_bits'])+float(json.loads(r['actual_log2_weights'])[0])
  runs+=records;layers+=list(csv.DictReader((f.parent/'layers.csv').open()))
  for name in ['task.json','unit.json','selected_settings.json','summary.json','certificate.json']:
   p=f.parent/name
   if p.exists():shutil.copy2(p,configs/(t['id']+'_'+name))
  for r in chosen+neighbor:
   q=list(map(str,json.loads(r['Q'])));p=list(map(str,json.loads(r['P'])));qp=math.prod(map(int,q+p))
   security.append(dict(id=t['id']+'_q'+str(r['bottom_budget_bits']),parameters=dict(n=t['N'],Q=q,P=p,qp_exact=str(qp))))
 seen=set();unique=[]
 for b in security:
  key=(b['parameters']['n'],tuple(b['parameters']['Q']),tuple(b['parameters']['P']))
  if key not in seen:unique.append(b);seen.add(key)
 for r,b in [(1,20)]+[(r,b) for r in [2,4] for b in [10,0,-10,-20]]:
  u=unit(r,b);units.append(dict(classes=r,nominal_mean_bits=b,nominal_targets=u['target_bits'],ideal_log2_weights=u['target_log2_weights'],actual_log2_weights=u['actual_log2_weights_display'],coefficient_bits=u['coefficient_bits'],inverse_coefficient_bits=max(abs(int(x)).bit_length() for x in u['inverse_coefficients']),exact_inverse_pass=u['inverse_identity_pass']))
 tables(out/'runs.csv',runs);tables(out/'layers.csv',layers);tables(out/'summary.csv',summaries);tables(out/'units.csv',units)
 # Group identical estimator inputs so one job can reuse them directly.
 buckets={}
 for b in unique:buckets.setdefault((b['parameters']['n'],int(b['parameters']['qp_exact']).bit_length()),[]).append(b)
 sp=out/'security_plans';sp.mkdir()
 for i,(key,branches) in enumerate(sorted(buckets.items())):dump(sp/f'plan_{i:03d}.json',dict(branches=branches))
 dump(out/'experiment_summary.json',dict(completed_cells=len(cells),run_count=len(runs),layer_count=len(layers),security_plan_count=len(buckets),exact_security_cases=len(unique),candidate_verified=sum(r['candidate_verified'] for r in summaries),final20_verified=sum(r['final20_verified'] for r in summaries)))
 print(json.dumps(json.loads((out/'experiment_summary.json').read_text()),indent=2))
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--source',required=True);a.add_argument('--out',required=True);a.add_argument('--expected',type=int,default=72);v=a.parse_args();export(v.source,v.out,v.expected)
