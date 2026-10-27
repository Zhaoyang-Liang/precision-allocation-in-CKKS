"""Check compact exports, exact security inputs and five-repeat bookkeeping."""
import argparse,csv,hashlib,json,math
from pathlib import Path
from zero_mean_experiment import tables,dump

def export_or_compare(path, rows):
 """Allow repeated audits without overwriting archived CSV data."""
 tmp=path.with_suffix(".audit-tmp")
 try:
  tables(tmp,rows)
  if path.exists():
   assert path.read_bytes()==tmp.read_bytes(), f"Archived CSV differs: {path}"
  else:
   tmp.rename(path)
 finally:
  if tmp.exists():tmp.unlink()

def audit(root):
 root=Path(root);data=root/'result/source_data';meta=root/'result/metadata'
 runs=list(csv.DictReader((data/'runs.csv').open()));layers=list(csv.DictReader((data/'layers.csv').open()));summary=list(csv.DictReader((data/'summary.csv').open()))
 assert len(summary)==72 and len({s['task_id'] for s in summary})==72
 assert len({(r['task_id'],r['trial']) for r in runs})==len(runs)
 assert all(l['integer_congruence_pass']=='True' for l in layers)
 for s in summary:
  rr=[r for r in runs if r['task_id']==s['task_id'] and r['selected_validation']=='True'];assert len(rr)==5
  assert sum(r['restoration_pass']=='True' for r in rr)==int(s['formal_recovery_count'])
  assert sum(r['target_20_bits_pass']=='True' for r in rr)==int(s['formal_target20_count'])
  for r in rr:
   ll=[l for l in layers if l['task_id']==r['task_id'] and l['trial']==r['trial']]
   assert [int(l['depth']) for l in ll]==list(range(len(ll)))
   assert r['restoration_pass']==str(int(ll[-1]['depth'])==int(r['depth']) and ll[-1]['wrap']=='False')
   assert r['target_20_bits_pass']==str(r['restoration_pass']=='True' and float(r['actual_precision_bits'])>=20)
   assert float(r['QP_bits'])<=856
 securities={};security_rows=[];commits=set();files=list((meta/'security').glob('plan_*.json'))
 assert len(files)==json.loads((meta/'experiment_summary.json').read_text())['security_plan_count']
 for f in files:
  d=json.loads(f.read_text());assert d['schema']=='ckks-new-security-v1' and d['model']=='RC.MATZOV' and d['secret']=='uniform_ternary' and d['target_bits']==128 and not d['estimator_tracked_dirty']
  commits.add(d['estimator_commit'])
  for c in d['cases']:
   qp=math.prod(map(int,c['Q']+c['P']));assert qp==int(c['qp_exact']) and (qp-1).bit_length()==c['q_est_log2']
   assert set(c['attacks'])=={'primal_usvp','primal_bdd','dual_hybrid'}
   for a in c['attacks'].values():
    v=float(a['log2_rop']);assert not math.isnan(v)
    if math.isfinite(v):assert v>=128 and a['target_pass']
    else:assert v>0 and not a['target_pass']
   assert c['N']==32768 and c['q_est_log2']<=856
   key=(c['N'],tuple(c['Q']),tuple(c['P']));v=min(float(a['log2_rop']) for a in c['attacks'].values());securities[key]=v
   security_rows.append(dict(case_id=c['branch'],N=c['N'],QP_log2_ceiling=c['q_est_log2'],min_security_bits=v if all(math.isfinite(float(a['log2_rop'])) for a in c['attacks'].values()) else '',primal_usvp_bits=c['attacks']['primal_usvp']['log2_rop'],primal_bdd_bits=c['attacks']['primal_bdd']['log2_rop'],dual_hybrid_bits=c['attacks']['dual_hybrid']['log2_rop'],all_three_finite=all(math.isfinite(float(a['log2_rop'])) for a in c['attacks'].values()),direct_estimator_status='finite_pass' if all(math.isfinite(float(a['log2_rop'])) for a in c['attacks'].values()) else 'nonfinite_cost_unavailable',published_classical128_parameter_check=True,published_QP_cap_bits=868,published_guideline_url='https://cic.iacr.org/p/1/4/26/pdf',Q=c['Q'],P=c['P'],estimator_commit=d['estimator_commit'],source_file=f.name,source_sha256=hashlib.sha256(f.read_bytes()).hexdigest()))
 assert len(commits)==1
 envelope=json.loads((meta/'security_envelope.json').read_text());ea=envelope['cases'][0]['attacks']
 assert envelope['cases'][0]['q_est_log2']==856 and all(math.isfinite(float(a['log2_rop'])) and float(a['log2_rop'])>=128 for a in ea.values())
 guideline=json.loads((meta/'security_model.json').read_text());assert guideline['guideline_max_log2_QP']==868 and guideline['table']=='5.2'
 for r in runs:
  if r['selected_validation']=='True' or r['lower_neighbor_validation']=='True':
   key=(int(r['N']),tuple(map(str,json.loads(r['Q']))),tuple(map(str,json.loads(r['P']))));assert key in securities
 export_or_compare(data/'security.csv',security_rows)
 result=dict(pass_all=True,tasks=len(summary),HE_runs=len(runs),integer_shadow_layers=len(layers),formal_trials=sum(r['selected_validation']=='True' for r in runs),candidate_recovery_verified=sum(s['candidate_verified']=='True' for s in summary),candidate_20bit_verified=sum(s['final20_verified']=='True' for s in summary),exact_security_estimator_inputs=len(files),exact_security_cases=len(securities),exact_cases_with_all_finite_costs=sum(r['all_three_finite'] for r in security_rows),exact_cases_with_nonfinite_costs=sum(not r['all_three_finite'] for r in security_rows),security_basis='Published Table 5.2 classical-128 parameter guideline; QP <=856 <868',envelope_min_finite_security_bits=min(float(a['log2_rop']) for a in ea.values()),point_estimator_commit=next(iter(commits)),envelope_estimator_commit=envelope['estimator_commit'],checks=['72 unique task cells','five independent final observations per cell','recorded recovery matches depth and exact shadow wrap flags','20-bit test separate from recovery','all integer congruence checks passed','all selected and neighboring exact Q/P cases matched explicit estimator records; nonfinite costs retained as unavailable','all experimental QP values fall below the published classical-128 parameter cap','the registered QP upper endpoint has three finite >=128-bit estimates'],scope='Five sampled encryptions at selected points, for the fixed 256-value plaintext set and declared scale/schedule family; not a uniform success theorem or global minimum Q.')
 print(json.dumps(result,indent=2,ensure_ascii=False))
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--root',default=str(Path(__file__).resolve().parent.parent));v=a.parse_args();audit(v.root)
