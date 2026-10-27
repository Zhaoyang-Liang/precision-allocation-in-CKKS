#!/usr/bin/env python3
"""Conditional exact public envelopes; decisions never use display logarithms.

The backend CRT/ModDown and encoder contracts are explicitly conditional.
No secret keys, HE execution, RMS inference, or independent-digit assumption.
"""
import json,math,argparse,hashlib
from fractions import Fraction as F
from pathlib import Path
from multip_contract import phase as audited_phase, validate as validate_backend
U=F(1,2**53)
PI_LO=F('3.14159265358979323846264338327950288')
D2=2**512; S2LO=F(math.isqrt(2*D2*D2),D2);S2HI=S2LO+F(1,D2)
CAP={8192:218,16384:438,32768:881};BS={8192:1024,16384:1450,32768:2000}
def gamma(k):return k*U/(1-k*U)
def ceil(x):return -(-x.numerator//x.denominator)
def upper(x,bits=256):return F(ceil(x*2**bits),2**bits)
def bits(x):return None if x==0 else -math.log2(x.numerator)+math.log2(x.denominator)
def cn(n):
 t=PI_LO/(2*n);return ceil(1/(t-t**3/6))
def qupper(a,b):return a+b*(S2HI if b>=0 else S2LO)
def weights(c):
 if c['kind'].startswith('ordinary'):return [F(1),F(1)]
 if c['kind']=='diagonal':
  g,f=c['dyadic_bits'],c['multiplier_scale_bits'];a=F(2**(f+g)+2**(f-g),2);v=F(2**(f+g)-2**(f-g),2)
  if a.denominator!=1 or v.denominator!=1:raise ValueError('unsupported half-integer diagonal coefficient')
  b=math.isqrt(v.numerator*v.numerator//2);b+=2*v.numerator*v.numerator>=(2*b+1)**2
  return [qupper(a/2**f,F(b,2**f)),qupper(a/2**f,F(-b,2**f))]
 a,b=1,0
 for _ in range(c['unit_power']):a,b=a+2*b,a+b
 if c['kind']=='integer_nonunit':a,b=2*a+2*b,a+2*b
 return [qupper(F(a),F(b)),qupper(F(a),F(-b))]
def rescale_factor(primes):
 # Deletion order is top-to-bottom; earlier rounding is divided again.
 e=F(0)
 for prime in reversed(primes):e=e/prime+1
 return e

def phase(n,q,p):
 return audited_phase(n,q,p,cn(n),BS[n])
def certify_branch(s,c,b,pb):
 p=pb['parameters'];n=p['n'];q=list(map(int,p['Q']));aux=list(map(int,p['P']));Q=math.prod(q)
 if len(set(q+aux))!=len(q+aux):raise ValueError('overlapping Q/P')
 validate_backend(n,q,aux)
 groups=[0,1] if b['group']=='all' else [int(b['group']=='high')]
 ws=weights(c);traj=pb['metadata_trajectory'];D=F(traj[0]['scale_exact']);ph=phase(n,q,aux)
 E=[upper(w*(ph['encoding']+ph['pk'])/D) for w in ws]
 rows=[];reasons=[];secure=math.prod(q+aux)<2**CAP[n]
 if not secure:reasons.append('documented_QP_security_cap_exceeded')
 resources={'n':n,'input_Q_count':len(q),'P_count':len(aux),'input_payload_bytes':str(16*n*len(q)),
 'relin_key_coefficient_payload_bytes':str(16*n*((len(q)+len(aux)-1)//len(aux))*(len(q)+len(aux))),
 'public_key_coefficient_payload_bytes':str(16*n*(len(q)+len(aux))),
 'work_Q_counts':[],'ciphertext_multiplications':0,'public_component_products':0,'public_pointwise_words':0}
 if b.get('algorithm')=='chebyshev6':
  from poly_certificate import certify_graph
  ledger=certify_graph(pb,phase,cn,BS,upper,s['target_bits_low_high'][0])
  if b.get('output_rescale_count',0) or b.get('output_drop_primes',0):reasons.append('post_polynomial_level_change_not_in_graph_contract')
  if not ledger['pass']:reasons.append('current_polynomial_error_or_range_bound_exceeds_target')
  resources['output_payload_bytes']=str(16*n*(ledger['output_level']+1))
  resources['ciphertext_multiplications']=ledger['operation_counts'].get('ciphertext_products',0)
  resources['work_Q_counts']=[node['state']['level']+1 for node in pb['polynomial_graph']['nodes'] if node['op']=='mul' and 'ideal_scalar_exact' not in node]
  return {'branch':b['id'],'status':'conditional_pass' if not reasons else 'not_certified','reasons':reasons,'security_cap_pass':secure,'resources':resources,'polynomial_ledger':ledger,'precision_bits_display':[bits(F(ledger['total_error_upper'])),None]}

 A=F(7,8);level=len(q)-1;correction=2**c.get('multiplier_scale_bits',0) if c['kind']=='diagonal' else 1
 for k,count in enumerate(b['rescale_counts']):
  ph=phase(n,q[:level+1],aux);divisor=math.prod(q[level-count+1:level+1]) if count else 1
  nextD=F(next(t['scale_exact'] for t in traj if t['stage']==f'square_{k+1}'))
  rho=D*D*correction/divisor/nextD
  old=[upper(abs(rho)*(2*A*e+e*e)) for e in E]
  ks=[upper(w*ph['ks']/divisor/nextD) for w in ws]
  rs=[upper(w*ph['rescale']*rescale_factor(q[level-count+1:level+1])/nextD) if count else F(0) for w in ws]
  meta=upper(abs(rho-1)*A*A)
  E=[upper(old[j]+ks[j]+rs[j]+meta) for j in range(2)]
  resources['work_Q_counts'].append(level+1);resources['ciphertext_multiplications']+=1
  if c['kind'] in ('unit','integer_nonunit','diagonal'):resources['public_component_products']+=3;resources['public_pointwise_words']+=3*n*(level+1)
  rows.append({'layer':k+1,'Q_before':level+1,'Q_after':level+1-count,'scale_before_exact':str(D),'scale_after_exact':str(nextD),
    'rho_exact':str(rho),'propagated_old_error':[str(x) for x in old],'KS_ModDown_new_error':[str(x) for x in ks],
    'normal_rescale_new_error':[str(x) for x in rs],'scale_metadata_new_error':str(meta),'total_error':[str(x) for x in E]})
  level-=count;D=nextD;A*=A
 if c['kind'] in ('unit','integer_nonunit','diagonal'):
  resources['public_component_products']+=2;resources['public_pointwise_words']+=2*n*(level+1)
 if c['kind']=='diagonal':D*=correction
 # Final divisions are sequential only when an operation separates them.
 for cnt in (b.get('restore_rescale_count',0),b.get('output_rescale_count',0)):
  if cnt:
   dd=math.prod(q[level-cnt+1:level+1]);D/=dd;E=[upper(e+ph['rescale']*rescale_factor(q[level-cnt+1:level+1])/D) for e in E];level-=cnt
 level-=b.get('output_drop_primes',0)
 finalD=F(traj[-1]['scale_exact']);ratio=D/finalD
 E=[upper(abs(ratio)*e+abs(ratio-1)*A) for e in E]
 Q=math.prod(q[:level+1]);range_ratio=max(2*finalD*(A+e)/Q for e in E)
 errorpass=all(E[j]<=F(1,2**s['target_bits_low_high'][j]) for j in groups)
 if not errorpass:reasons.append('current_error_upper_bound_exceeds_target')
 if range_ratio>=1:reasons.append('final_logical_embedding_sufficient_range_test_failed')
 resources['output_payload_bytes']=str(16*n*(level+1))
 return {'branch':b['id'],'status':'conditional_pass' if not reasons else 'not_certified','reasons':reasons,
  'security_cap_pass':secure,'resources':resources,'final_error_upper_exact':[str(x) for x in E],
  'precision_bits_display':[bits(x) for x in E],'range_ratio_upper_exact':str(range_ratio),
  'initial_error_terms':{'encoding_phase':str(phase(n,q,aux)['encoding']),'PK_phase':str(phase(n,q,aux)['pk'])},'layers':rows}

def certify(s,plan):
 rows=[]
 for c,p in zip(s['cases'],plan['cases'],strict=True):
  if c['id']!=p['id']:raise ValueError('case mismatch')
  bs=[certify_branch(s,c,b,pb) for b,pb in zip(c['branches'],p['branches'],strict=True)]
  rows.append({'case':c['id'],'kind':c['kind'],'status':'conditional_pass' if all(b['status']=='conditional_pass' for b in bs) else 'not_certified','branches':bs})
 return {'schema':'conditional-pow16-screen-v3','HE_executions':'0','unconditional_certificate':False,
 'scope':'Exported fixed-circuit and polynomial DAG bounds; failures never prove algorithmic impossibility.',
 'assumptions':['Scaled encoder coefficient error <=1, not numerically certified FFT.',
 'Lattigo v6.2.0 no-bit CRT/ModDown source-derived envelope, 1..10 P, guarded integer ranges; uniform over adaptive inputs. See docs/02_proofs.md; encoder and sampled-key conditions remain.',
 'Reusable sampled-key event, <=64 secret-type polynomials and <=4096 evaluation error polynomials PER ring dimension within one configuration.',
 'Bs(8192,16384,32768)=(1024,1450,2000), Be=40000; six family failure bounds <=2^-140, union <2^-137 <2^-128.',
 'Security is documented uniform-ternary QP-cap screening, not a new lattice-estimator run.'],
 'rows':rows}

if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('config');a.add_argument('plan');a.add_argument('out');v=a.parse_args()
 s=json.loads(Path(v.config).read_text());p=json.loads(Path(v.plan).read_text());r=certify(s,p)
 r['config_sha256']=hashlib.sha256(Path(v.config).read_bytes()).hexdigest()
 r['plan_sha256']=hashlib.sha256(Path(v.plan).read_bytes()).hexdigest()
 with Path(v.out).open('x') as f:json.dump(r,f,indent=2);f.write('\n')
 print('conditional_pass',sum(x['status']=='conditional_pass' for x in r['rows']),'of',len(r['rows']))
