"""Deterministic native-encoding certificate for the audited Lattigo v6.2.0 path.

No ciphertexts, random keys or empirical error estimates. All acceptance
decisions use exact integers/Fractions with explicit outward rounding.
Scope: standard ring, full complex slots, big.Float nearest-even, 128..1024 bits,
exact rational business inputs, explicit integer a+b*h, actual rational scale.
"""
from fractions import Fraction as F
from functools import lru_cache
from pathlib import Path
import math, re, hashlib, json
from selector import pow2, floor_log2, round_binary

ROOT = Path(__file__).resolve().parents[1]

def rnd(x, precision):
    x=F(x)
    return F(0) if not x else (1 if x>0 else -1)*round_binary(abs(x),precision)

def upper(x, bits):
    return F(-(-(x*2**bits).numerator//(x*2**bits).denominator),2**bits)

@lru_cache(None)
def root_interval(bits):
    d=1<<bits; a=math.isqrt(2*d*d)
    return F(a,d),F(a+1,d)

def sqrt2_rounded(precision):
    # sqrt(2) is in [1,2); compare the exact squared midpoint.
    step=pow2(1-precision); n=math.isqrt(2*(1<<(precision-1))**2)
    if (F(n)+F(1,2))**2*step**2 < 2: n+=1
    return n*step

@lru_cache(None)
def pi_interval():
    def atan_inv(q, terms):
        s=sum((F((-1)**k,(2*k+1)*q**(2*k+1)) for k in range(terms)),F(0))
        t=F((-1)**terms,(2*terms+1)*q**(2*terms+1))
        return min(s,s+t),max(s,s+t)
    a,b=atan_inv(5,300);c,d=atan_inv(239,100)
    return 16*a-4*d,16*b-4*c

@lru_cache(None)
def root_error(precision):
    if not 128<=precision<=1024: raise ValueError('unsupported_arithmetic_precision')
    u=pow2(1-precision); m=precision//2-1; X=F(8,5)
    # (1+u)^r <= 1/(1-r*u) for nonnegative r*u<1.
    if (2*m+1)*u>=1 or X*X/(1-(2*m+1)*u)>=3:
        raise ValueError('cosine_recurrence_range_not_certified')
    source=(ROOT/'reference/lattigo/utils/bignum/float.go').read_text()
    literal=F(re.search(r'const pi = "([0-9.]+)"',source).group(1))
    pihat=rnd(literal,precision);lo,hi=pi_interval()
    ep=max(abs(pihat-lo),abs(pihat-hi))
    angle=ep/2+u*(hi+ep)/2
    if (hi+ep)*(1+u)/2>=X: raise ValueError('angle_range_not_certified')
    trunc=X**4/(24*4**m)
    floating=X*X/2*(u+m*(2*u+u*u)/(1-(2*m-1)*u))+u
    return { 'pi_float':pihat,'pi_error':upper(ep,precision+128),
             'angle_error':upper(angle,precision+128),
             'cos_truncation':upper(trunc,precision+128),
             'cos_rounding':upper(floating,precision+128),
             'root_component_error':upper(angle+trunc+floating,precision+128)}

def weight_data(a,b,precision):
    if not a and not b:raise ValueError('zero_multiplier')
    af=rnd(a,precision);bf=rnd(b,precision)
    term=rnd(sqrt2_rounded(precision)*bf,precision)
    floating=(rnd(af+term,precision),rnd(af-term,precision))
    lo,hi=root_interval(precision+512)
    rows=[]
    for sign,w in zip((1,-1),floating):
        ends=(F(a)+sign*b*lo,F(a)+sign*b*hi);left,right=min(ends),max(ends)
        if left<=0<=right or not w:raise ValueError('small_embedding_not_resolved')
        if (w>0)!=(left>0):raise ValueError('floating_weight_sign_mismatch')
        rows.append({'float':w,'abs_lower':min(abs(left),abs(right)),
                     'abs_upper':max(abs(left),abs(right)),
                     'absolute_error':max(abs(w-left),abs(w-right))})
    return rows

@lru_cache(None)
def certificate(n,precision,a,b,scale,amplitude=F(7,8)):
    scale=F(scale);amplitude=F(amplitude)
    if n<16 or n&(n-1) or n>2**30:raise ValueError('standard_power_of_two_ring_required')
    if scale<=0 or amplitude<0:raise ValueError('invalid_scale_or_input_range')
    # The actual metadata is a binary 128-bit big.Float value.
    if rnd(scale,128)!=scale:raise ValueError('scale_not_exact_128_bit_metadata')
    roots=root_error(precision);weights=weight_data(a,b,precision)
    u=pow2(1-precision); wb=precision+192; slots=n//2
    zeta=F(0);Z=F(0)
    for w in weights:
        wf=abs(w['float']);tau=w['absolute_error']
        zeta=max(zeta,amplitude*((2*u+u*u)/wf+tau/(w['abs_lower']*wf)))
        Z=max(Z,amplitude*(1+u)**2/wf)
    zeta=upper(zeta,wb);Z=upper(Z,wb)
    beta=upper(4*(1+roots['root_component_error'])*(1+u)**3,wb)
    E=zeta;B=Z
    for _ in range(slots.bit_length()-1):
        E=upper(4*E+(beta-4)*B,wb)
        B=upper(beta*B,wb)
    E=upper(E/slots,wb);B=upper(B/slots,wb)
    rounding=upper((2*u+u*u)*scale*B+u/2,wb)
    excess=upper(scale*E+rounding,wb)
    total=F(1,2)+excess
    return {'status':'encoding_bound_le_one' if total<=1 else 'encoding_bound_not_le_one',
            'N':str(n),'precision':str(precision),'a':str(a),'b':str(b),
            'scale':str(scale),'component_amplitude':str(amplitude),
            'weight_data':[{k:str(v) for k,v in w.items()} for w in weights],
            'roots':{k:str(v) for k,v in roots.items()},
            'input_transform_component_error':str(zeta),'stored_component_bound':str(Z),
            'IFFT_component_error':str(E),'IFFT_computed_component_bound':str(B),
            'final_float_rounding_error':str(rounding),
            'coefficient_error_upper':str(total),'excess_above_half':str(excess),
            'excess_bits_display':-math.log2(excess) if excess else None,
            'random_failure_probability':'0',
            'scope':'audited native input path; not evaluator constants, decode, or float64 input'}

def verify_source_hashes():
    manifest=json.loads((ROOT/'reference/source_contract.json').read_text())
    for r in manifest['files']:
        p=ROOT/'reference/lattigo'/r['path']
        if hashlib.sha256(p.read_bytes()).hexdigest()!=r['sha256']:
            raise ValueError('audited_source_hash_mismatch:'+r['path'])
    for r in manifest.get('runner_files',[]):
        if hashlib.sha256((ROOT/'reference'/r['path']).read_bytes()).hexdigest()!=r['sha256']:
            raise ValueError('runner_source_hash_mismatch:'+r['path'])
    return True
