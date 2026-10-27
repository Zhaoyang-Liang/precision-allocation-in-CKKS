#!/usr/bin/env python3
"""Finite public parameter selector, conditional on the inherited contracts.

No HE, secrets, random key sampling or timing predictions. Prime, scale, error
and threshold decisions use integers/Fractions. Unit powers are positive even
integers 2..128, matching the existing runner; k=0 is ordinary CKKS.
"""
from fractions import Fraction as F
from functools import lru_cache
from dataclasses import dataclass
import math
from multip_contract import is_prime64, validate, phase, workload
from certify import cn, BS, CAP

PREC = 256
ROOT_DEN = 2**512
ROOT_LO = F(math.isqrt(2*ROOT_DEN**2), ROOT_DEN)
ROOT_HI = ROOT_LO + F(1, ROOT_DEN)

def pow2(b): return F(2**b) if b >= 0 else F(1, 2**(-b))
def ceil(x): return -(-x.numerator // x.denominator)
def up(x): return F(ceil(x * 2**PREC), 2**PREC)
def display_bits(x): return None if x == 0 else math.log2(x.denominator)-math.log2(x.numerator)

def floor_log2(x):
    if x <= 0: raise ValueError('positive scale required')
    b=x.numerator.bit_length()-x.denominator.bit_length()
    if x < pow2(b): b-=1
    return b

def round_binary(x, precision=128):
    """Exact round-to-nearest, ties-to-even for positive big.Float metadata."""
    if x <= 0: raise ValueError('positive metadata required')
    step=pow2(floor_log2(x)-precision+1)
    y=x/step; a,r=divmod(y.numerator,y.denominator)
    if 2*r > y.denominator or (2*r == y.denominator and a%2): a+=1
    return a*step

@lru_cache(None)
def weight_upper(k):
    """(low, high) magnitudes; also valid for odd k, unlike signed embeddings."""
    if k < 0: return weight_upper(-k)[::-1]
    a,b=1,0
    for _ in range(k): a,b=a+2*b,a+b
    large=F(a)+b*ROOT_HI
    small=F(a)-b*ROOT_LO if k%2 == 0 else -F(a)+b*ROOT_HI
    return up(large), up(small)

@lru_cache(None)
def prime_pool(n, bits):
    if not 24 <= bits <= 60: raise ValueError('outside declared width family')
    step=2*n; v=((2**bits-2)//step)*step+1; out=[]
    while v >= 2**(bits-1) and len(out)<80:
        if is_prime64(v): out.append(v)
        v-=step
    if not out: raise ValueError('empty prime pool')
    return tuple(out)

def allocate_primes(n, widths, excluded=()):
    used=set(excluded); out=[]
    for width in widths:
        p=next((p for p in prime_pool(n,width) if p not in used),None)
        if p is None: raise ValueError('no unused prime')
        out.append(p);used.add(p)
    return tuple(out)

def balanced_widths(total, maximum=60):
    length=(total+maximum-1)//maximum
    if length<1: raise ValueError('empty basis')
    a,r=divmod(total,length)
    widths=[a+1]*r+[a]*(length-r)
    if min(widths)<24: raise ValueError('limb below selected 24-bit floor')
    return widths

def balanced_p(n,q,m,total):
    a,r=divmod(total,m)
    if a<24 or a+(r>0)>60: raise ValueError('P width outside selected family')
    return allocate_primes(n,[a+1]*r+[a]*(m-r),q)

@dataclass(frozen=True)
class Plan:
    name: str
    n: int
    q: tuple
    counts: tuple
    scales: tuple
    nominal: tuple
    amplitude: F=F(7,8)

    def serial(self):
        return {'id':self.name,'n':str(self.n),'Q':[str(x) for x in self.q],
                'rescale_counts':[str(x) for x in self.counts],
                'actual_scales':[str(x) for x in self.scales],
                'nominal_scale_bits':[str(x) for x in self.nominal],
                'amplitude':str(self.amplitude)}

def scales_for(q,counts,initial):
    D=initial;L=len(q); scales=[D]
    for count in counts:
        if count<0 or count>=L: raise ValueError('rescale exhausts Q')
        D=round_binary(D*D)
        for p in reversed(q[L-count:L]): D=round_binary(D/p)
        L-=count;scales.append(D)
    return tuple(scales)

def make_plan(n,base,shape='flat',depth=4,slack=0,maximum=60,amplitude=F(7,8)):
    if shape=='flat': s=[base]*(depth+1)
    elif shape=='taper': s=[base+8,base+4]+[base]*(depth-1)
    elif shape=='alternating': s=[base+(20 if t%2 else 0) for t in range(depth+1)]
    else: raise ValueError('unknown schedule shape')
    # Endpoint selected from ideal range, then rechecked including actual error.
    threshold=2*pow2(s[-1])*(amplitude**(2**depth)+pow2(-22))
    final_bits=floor_log2(threshold)+1+slack
    widths=balanced_widths(final_bits,maximum)
    blocks=[balanced_widths(2*s[t]-s[t+1],maximum) for t in range(depth)]
    for block in reversed(blocks): widths+=block
    q=allocate_primes(n,widths)
    counts=tuple(map(len,blocks))
    name=f'n{n.bit_length()-1}_b{base}_{shape}_d{depth}_f{slack}_limb{maximum}'
    return Plan(name,n,q,counts,scales_for(q,counts,pow2(s[0])),tuple(s),amplitude)

def imported_plan(case,pb):
    b=case['branches'][0]; p=pb['branches'][0]; tr=p['metadata_trajectory']
    scales=tuple(F(x['scale_exact']) for x in tr if x['stage']=='input' or x['stage'].startswith('square_'))
    return Plan(case['id'],p['parameters']['n'],tuple(map(int,p['parameters']['Q'])),
                tuple(b['rescale_counts']),scales,())

class Oracle:
    def __init__(self, plan, p, old=(F(0),F(0))):
        self.plan=plan;self.p=tuple(p);self.old=tuple(old)
        if len(self.old)!=2 or any(x<0 for x in self.old):raise ValueError('two_nonnegative_old_error_bounds_required')
        if plan.amplitude<0 or len(plan.scales)!=len(plan.counts)+1 or any(x<=0 for x in plan.scales):
            raise ValueError('invalid_message_or_scale_envelope')
        if tuple(plan.scales)!=scales_for(plan.q,plan.counts,plan.scales[0]):
            raise ValueError('metadata_not_the_declared_square_rescale_graph')
        validate(plan.n,plan.q,self.p)
        self.safe=math.prod(plan.q+self.p)<2**CAP[plan.n]
        C=cn(plan.n); B=BS[plan.n]; ph=phase(plan.n,plan.q,self.p,C,B)
        self.initial=(ph['encoding']+ph['pk'])/plan.scales[0]
        self.steps=[];L=len(plan.q);A=plan.amplitude
        for t,count in enumerate(plan.counts):
            ph=phase(plan.n,plan.q[:L],self.p,C,B)
            deleted=plan.q[L-count:L] if count else ()
            divisor=math.prod(deleted);nextD=plan.scales[t+1]
            rho=plan.scales[t]**2/(divisor*nextD)
            R=F(0)
            for q in reversed(deleted): R=R/q+1
            self.steps.append({'rho':rho,'A':A,'ks':ph['ks']/(divisor*nextD),
                              'rs':ph['rescale']*R/nextD,'meta':abs(rho-1)*A*A,
                              'Q_count':L,'d':divisor})
            L-=count;A*=A
        self.final_L=L;self.final_A=A;self.final_Q=math.prod(plan.q[:L])
        self.range_cap=F(self.final_Q,2)/plan.scales[-1]-A

    def error(self,weight,group=0,ledger=False):
        E=up(self.old[group]+weight*self.initial); rows=[]
        for s in self.steps:
            old=up(s['rho']*(2*s['A']*E+E*E))
            ks=up(weight*s['ks']);rs=up(weight*s['rs']);mu=up(s['meta'])
            E=up(old+ks+rs+mu)
            if ledger:rows.append({'old':str(old),'KS_ModDown':str(ks),'normal_rescale':str(rs),
                                   'metadata':str(mu),'total':str(E)})
        return (E,rows) if ledger else E

    def passes(self,k,targets=(22,72),groups=(0,1)):
        ws=weight_upper(k)
        for j in groups:
            e=self.error(ws[j],j)
            if e>pow2(-targets[j]) or e>=self.range_cap:return False
        return True

    def unit_interval(self,targets=(22,72),max_power=128):
        """Contiguous even powers. At most 2 log2(64)+O(1) group checks."""
        if max_power<2 or max_power%2:raise ValueError('positive even upper endpoint required')
        lo,hi=1,max_power//2
        if not self.passes(2*hi,targets,(1,)) or not self.passes(2,targets,(0,)):return None
        a,b=lo,hi
        while a<b:
            mid=(a+b)//2
            if self.passes(2*mid,targets,(1,)):b=mid
            else:a=mid+1
        left=a
        a,b=lo,hi
        while a<b:
            mid=(a+b+1)//2
            if self.passes(2*mid,targets,(0,)):a=mid
            else:b=mid-1
        return (2*left,2*a) if left<=a else None

    def record(self,k,targets=(22,72),groups=(0,1)):
        es=[];ledgers=[]
        for j,w in enumerate(weight_upper(k)):
            e,ledger=self.error(w,j,True);es.append(e);ledgers.append(ledger)
        reasons=[]
        if not self.safe:reasons.append('inherited_QP_screen_exceeded')
        if any(es[j]>pow2(-targets[j]) for j in groups):reasons.append('current_error_bound_does_not_certify')
        if any(es[j]>=self.range_cap for j in groups):reasons.append('final_sufficient_range_bound_does_not_certify')
        return {'status':'conditional_pass' if not reasons else 'not_certified','reasons':reasons,
                'weight_upper_low_high':[str(w) for w in weight_upper(k)],
                'error_upper_low_high':[str(e) for e in es],
                'precision_bits_display':[display_bits(e) for e in es],
                'range_error_cap':str(self.range_cap),'ledgers_low_high':ledgers,
                'resources':self.resources(k)}

    def resources(self,k):
        n=self.plan.n;L=len(self.plan.q);m=len(self.p)
        layers=[workload(n,self.plan.q[:s['Q_count']],self.p) for s in self.steps]
        keys=('gadget_pointwise_products','ks_forward_NTT_limbs','ks_inverse_NTT_limbs',
              'crt_multsum_terms_per_coefficient','singleton_decomposition_BRed_calls_per_coefficient')
        totals={k:str(sum(int(x[k]) for x in layers)) if all(x[k] is not None for x in layers) else None for k in keys}
        return {'n':str(n),'Q_count':str(L),'P_count':str(m),'QP_exact':str(math.prod(self.plan.q+self.p)),
                'relin_bytes':str(16*n*((L+m-1)//m)*(L+m)), 'public_key_bytes':str(16*n*(L+m)),
                'input_bytes':str(16*n*L),'output_bytes':str(16*n*self.final_L),
                'layers':layers,'ks_counts':totals,'square_calls':str(len(self.steps)),
                'tensor_work_words':str(n*sum(s['Q_count'] for s in self.steps)),
                'removed_Q_count':str(sum(self.plan.counts)),
                'correction_pointwise_words':str(3*n*sum(s['Q_count'] for s in self.steps)+2*n*self.final_L) if k else '0'}

def verify_telescoping(oracle):
    p=oracle.plan
    right=F(oracle.final_Q)/p.scales[-1]*p.scales[0]**2
    for scale in p.scales[1:-1]:right*=scale
    for s in oracle.steps:right/=s['rho']
    if right!=math.prod(p.q):raise AssertionError('telescoping identity failed')
    return True

def explain_rejection(o,representation,targets=(22,72),group=None):
    """Diagnostic decisions use exact bounds. No hypothetical HE failure."""
    def state(k,j):
        e=o.error(weight_upper(k)[j],j)
        return {'power':str(k),'group':str(j),'error_upper':str(e),
                'target_pass':e<=pow2(-targets[j]),'range_pass':e<o.range_cap}
    if representation!='unit':
        return {'reason':'ordinary_error_or_range_contract_not_met',
                'group_checks':[state(0,j) for j in ((group,) if group is not None else (0,1))]}
    if not o.passes(128,targets,(1,)):
        return {'reason':'high_group_not_certified_even_at_maximum_allowed_power','endpoint':state(128,1)}
    if not o.passes(2,targets,(0,)):
        return {'reason':'low_group_not_certified_even_at_minimum_allowed_power','endpoint':state(2,0)}
    a,b=1,64
    while a<b:
        mid=(a+b)//2
        if o.passes(2*mid,targets,(1,)):b=mid
        else:a=mid+1
    left=2*a;a,b=1,64
    while a<b:
        mid=(a+b+1)//2
        if o.passes(2*mid,targets,(0,)):a=mid
        else:b=mid-1
    right=2*a
    if left<=right:raise AssertionError('cannot explain rejection of a feasible interval')
    return {'reason':'integer_unit_intervals_do_not_overlap',
            'minimum_power_for_high':str(left),'maximum_power_for_low':str(right),
            'low_at_required_high_power':state(left,0),'high_at_maximum_low_power':state(right,1)}

def search_p(plan,representation,targets=(22,72),group=None):
    """Boundary search in a declared componentwise-monotone balanced P family.

    All generated P vectors in the relevant width interval are validated before
    binary searching; invalid backend vectors abort that cell, not a false
    monotonicity inference. Every actually evaluated certificate is retained.
    """
    tested=[];boundaries=[]
    for m in range(1,min(10,len(plan.q))+1):
        low,high=24*m,60*m
        safe_budgets=[];previous=None
        for B in range(low,high+1):
            ps=balanced_p(plan.n,plan.q,m,B);validate(plan.n,plan.q,ps)
            if previous is not None and not all(x<=y for x,y in zip(previous,ps)):
                raise AssertionError('P family not componentwise monotone')
            previous=ps
            if math.prod(plan.q+ps)<2**CAP[plan.n]:safe_budgets.append(B)
            else:break
        if not safe_budgets:
            boundaries.append({'m':str(m),'status':'no_safe_vector_in_declared_width_family'});continue
        safe=safe_budgets[-1];cache={}
        def check(B):
            if B in cache:return cache[B]
            ps=balanced_p(plan.n,plan.q,m,B);o=Oracle(plan,ps)
            if representation=='unit':
                interval=o.unit_interval(targets);ok=interval is not None;k=interval[0] if ok else 2
            else:
                interval=None;k=0;ok=o.passes(k,targets,(group,) if group is not None else (0,1))
            row={'plan':plan.name,'representation':representation,'group':None if group is None else str(group),
                 'm':str(m),'nominal_P_bits':str(B),'P':[str(p) for p in ps],
                 'status':'conditional_pass' if ok else 'not_certified_under_current_bound',
                 'unit_interval':None if interval is None else [str(x) for x in interval],
                 'chosen_power':str(k) if ok else None,'resources':o.resources(k)}
            if ok:
                row['certificate']=o.record(k,targets,(group,) if group is not None else (0,1))
                if row['certificate']['status']!='conditional_pass':raise AssertionError('selector and certificate disagree')
            else:row['rejection_diagnostic']=explain_rejection(o,representation,targets,group)
            tested.append(row);cache[B]=row
            return row
        top=check(safe)
        if top['status']!='conditional_pass':
            boundaries.append({'m':str(m),'status':'not_certified_even_at_largest_safe_P','witness_P_bits':str(safe)});continue
        a,b=low,safe
        while a<b:
            mid=(a+b)//2
            if check(mid)['status']=='conditional_pass':b=mid
            else:a=mid+1
        first=check(a)
        if a>low:check(a-1)
        boundaries.append({'m':str(m),'status':'conditional_pass','first_P_bits':str(a),'last_safe_P_bits':str(safe),
                           'witness':first})
    return {'plan':plan.serial(),'representation':representation,'group':None if group is None else str(group),
            'targets_low_high':[str(x) for x in targets],'evaluations':tested,'boundaries':boundaries}
