"""Exact certificate for the exported *official* Lattigo degree-six DAG.

No independence assumption. Complex input perturbations are handled on a disk.
A rejection is a failure of this sufficient bound, never an impossibility.
"""
from fractions import Fraction as F
from math import comb,prod
from collections import Counter

def padd(a,b):
 c=[F(0)]*max(len(a),len(b))
 for i,v in enumerate(a):c[i]+=v
 for i,v in enumerate(b):c[i]+=v
 while len(c)>1 and c[-1]==0:c.pop()
 return c

def pscale(a,s):return [v*s for v in a]
def pmul(a,b):
 c=[F(0)]*(len(a)+len(b)-1)
 for i,x in enumerate(a):
  for j,y in enumerate(b):c[i+j]+=x*y
 return c

def real_bound(p):
 # Convex hull of exact Bernstein coefficients on 16 subintervals.
 d=len(p)-1
 if d==0:return abs(p[0])
 out=F(0)
 for seg in range(16):
  a=F(-1)+F(seg,8);h=F(1,8)
  c=[sum((p[k]*comb(k,i)*a**(k-i)*h**i for k in range(i,d+1)),F(0)) for i in range(d+1)]
  bs=[sum((c[i]*F(comb(j,i),comb(d,i)) for i in range(j+1)),F(0)) for j in range(d+1)]
  out=max(out,max(map(abs,bs)))
 return out

def bound(p,r):
 # r=1+delta denotes [-1,1] plus a complex disk, not the disk |z|<=r.
 delta=r-1
 if delta<0:raise ValueError('negative perturbation radius')
 total=F(0)
 for j in range(len(p)):
  derivative_over_factorial=[p[k]*comb(k,j) for k in range(j,len(p))]
  total+=real_bound(derivative_over_factorial)*delta**j
 return total
def exact_cheb6():
 a=[F(0)]*17
 for n in range(17):
  v=F(comb(16,n)*13**(16-n),16**16)
  for k in range(n//2+1):
   j=n-2*k;a[j]+=v*F(comb(n,k)*(2 if j else 1),2**n)
 ts=[[F(1)],[F(0),F(1)]]
 for k in range(2,7):ts.append(padd([F(0)]+pscale(ts[-1],2),pscale(ts[-2],-1)))
 p=[F(0)]
 for v,t in zip(a,ts):p=padd(p,pscale(t,v))
 return p,sum(a[7:])

def certify_graph(pb,phase,cn,BS,upper,target):
 p=pb['parameters'];n=p['n'];q=list(map(int,p['Q']));aux=list(map(int,p['P']));graph=pb['polynomial_graph'];nodes=graph['nodes']
 if not nodes or nodes[0]['op']!='input':raise ValueError('missing graph input')
 D0=F(nodes[0]['state']['scale_exact']);ph=phase(n,q,aux);ein=upper((ph['encoding']+ph['pk'])/D0)
 delta=16*ein;radius=1+delta
 polynomials=[];errors=[];rows=[];counts=Counter();kscalls=0
 cats=('KS_ModDown','normal_rescale','scalar_quantization_and_metadata')
 def zero():return {k:F(0) for k in cats}
 for i,node in enumerate(nodes):
  counts['internal_scale_alignment_scalar_multiplications']+=node.get('internal_scale_alignment_scalar_multiplications',0)
  if node['id']!=i or any(j>=i or j<0 for j in (node['inputs'] or [])):raise ValueError('non-topological graph')
  ids=node['inputs'] or [];op=node['op'];s=node['state'];D=F(s['scale_exact']);err=zero();local=zero()
  f=F(node.get('factor_exact','1'));h=F(node.get('accumulator_factor_exact','1'))
  if D<=0 or not 0<=s['level']<len(q):raise ValueError('invalid graph metadata')
  if op=='input':ideal=[F(13,16),F(1,16)]
  elif op=='zero':ideal=[F(0)]
  else:
   ia=ids[0];a=polynomials[ia];ea=errors[ia];A=bound(a,radius)
   if op in ('relinearize','rescale','metadata'):
    ideal=a;err={k:abs(f)*ea[k] for k in cats};local[cats[2]]=abs(f-1)*A
   elif op in ('add','sub'):
    if 'ideal_scalar_exact' in node:
     v=F(node['ideal_scalar_exact']);ideal=padd(a,[v]);err=ea.copy();local[cats[2]]=abs(F(node['constant_exact'])-v)
    else:
     ib=ids[1];b=polynomials[ib];sign=1 if op=='add' else -1;ideal=padd(a,pscale(b,sign));err={k:abs(f)*ea[k]+abs(h)*errors[ib][k] for k in cats};local[cats[2]]=abs(f-1)*A+abs(h-sign)*bound(b,radius)
   elif op in ('mul','mul_then_add'):
    if 'ideal_scalar_exact' in node:
     v=F(node['ideal_scalar_exact']);ideal=pscale(a,v);err={k:abs(f)*ea[k] for k in cats};local[cats[2]]=abs(f-v)*A
     if op=='mul_then_add':
      ib=ids[-1];ideal=padd(ideal,polynomials[ib]);err={k:err[k]+abs(h)*errors[ib][k] for k in cats};local[cats[2]]+=abs(h-1)*bound(polynomials[ib],radius)
    else:
     ib=ids[1];b=polynomials[ib];eb=errors[ib];B=bound(b,radius);Eb=sum(eb.values());ideal=pmul(a,b)
     err={k:abs(f)*((B+Eb)*ea[k]+A*eb[k]) for k in cats};local[cats[2]]=abs(f-1)*A*B;counts['ciphertext_products']+=1
   else:raise ValueError('unknown graph operation '+op)
   if node['relinearization']:
    level=min(nodes[j]['state']['level'] for j in ids);local[cats[0]]=phase(n,q[:level+1],aux)['ks']/D;kscalls+=1
   if op=='rescale':
    l=nodes[ia]['state']['level'];primes=list(map(int,node['removed_primes']));expected=list(reversed(q[s['level']+1:l+1]))
    if primes!=expected:raise ValueError('rescale prime sequence mismatch')
    factor=F(0)
    for prime in primes:factor=factor/prime+1
    degree=nodes[ia]['state']['degree'];H=F(cn(n),2)*sum(BS[n]**k for k in range(degree+1))
    local[cats[1]]=H*factor/D;counts['rescale_prime_steps']+=len(primes)
  for k in cats:err[k]=upper(err[k]+local[k])
  polynomials.append(ideal);errors.append(err);counts[op]+=1
  rows.append({'node':i,'op':op,'inputs':ids,'level':s['level'],'degree':s['degree'],'scale_exact':str(D),'ideal_polynomial_in_t':[str(x) for x in ideal], 'complex_neighborhood_amplitude_upper':str(upper(bound(ideal,radius))), 'local_error_terms':{k:str(v) for k,v in local.items()},'cumulative_error_terms':{k:str(v) for k,v in err.items()}})
 out=graph['output_node'];poly,tail=exact_cheb6();impl=polynomials[out]
 # Coefficients in the scheduler are finite-precision big.Float values. Account
 # for their deviation from the exact P6 even before backend scalar rounding.
 coefficient_error=bound(padd(impl,pscale(poly,-1)),radius)
 inputprop=sum((real_bound([poly[k]*comb(k,j) for k in range(j,len(poly))])*delta**j for j in range(1,len(poly))),F(0))
 he=upper(sum(errors[out].values())+coefficient_error);total=upper(tail+inputprop+he)
 D=F(nodes[out]['state']['scale_exact']);level=nodes[out]['state']['level'];A=F(7,8)**16
 rr=2*D*(A+total)/prod(q[:level+1]);passing=total<=F(1,2**target) and rr<1
 return {'pass':passing,'total_error_upper':str(total),'approximation_error_upper':str(tail),'input_propagation_error_upper':str(upper(inputprop)), 'HE_evaluation_error_upper':str(he),'scheduler_coefficient_error_upper':str(coefficient_error),'input_error_upper':str(ein),'complex_t_radius':str(radius),'range_ratio_upper_exact':str(rr),'output_level':level,'operation_counts':dict(counts),'key_switch_calls':kscalls,'nodes':rows,
 'limitations':['Conditional backend and encoder contracts inherited; no numerical FFT certification.','No independence of slots, key errors, digits, or residuals is assumed.','Runtime graph must match this plan exactly.']}
