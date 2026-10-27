"""Uniform Lattigo 6.2.0 CRT/ModDown envelope, without independence assumptions.

Scope: 1..10 P primes, no bit decomposition, standard power-of-two ring,
binary64 round-to-nearest, 64-bit integer modular primitives. See docs/02_proofs.md.
This is NOT a numerical encoder certificate or a new security estimate.
"""
from fractions import Fraction as F
from functools import lru_cache
import math

U = F(1, 2**53)
MAX_P = 10
R64 = 2**64

def gamma(k):
    if k * U >= 1:
        raise ValueError('floating_error_model_out_of_range')
    return k * U / (1-k*U)

def crt_delta(r):
    if not 1 <= r <= 32:
        raise ValueError('CRT_scratch_array_length_exceeded')
    return r * gamma(r+3)

@lru_cache(None)
def is_prime64(n):
    """Deterministic Miller--Rabin for unsigned 64-bit integers."""
    if not 2 <= n < 2**64:
        return False
    for p in (2,3,5,7,11,13,17,19,23,29,31,37):
        if n % p == 0:
            return n == p
    d=n-1; s=0
    while d % 2 == 0:
        d//=2; s+=1
    for a in (2,325,9375,28178,450775,9780504,1795265022):
        a%=n
        if not a:
            continue
        x=pow(a,d,n)
        if x in (1,n-1):
            continue
        for _ in range(s-1):
            x=x*x%n
            if x==n-1:
                break
        else:
            return False
    return True

def validate(n, q, p):
    q=tuple(q); p=tuple(p)
    if n < 16 or n & (n-1):
        raise ValueError('standard_power_of_two_ring_required')
    # In the direct-square graph, ModDown reconstructs the P basis and gadget
    # decomposition reconstructs blocks of at most len(P). Neither operation
    # reconstructs the entire Q basis. The backend's 32-element CRT scratch
    # arrays therefore still receive at most MAX_P=10 elements when Q has 64
    # limbs. This does NOT extend the contract to arbitrary full-Q ModUp calls.
    if not 1 <= len(p) <= MAX_P or not 1 <= len(q) <= 64:
        raise ValueError('outside_audited_modulus_count_scope')
    if len(set(q+p)) != len(q)+len(p):
        raise ValueError('overlapping_Q_P_primes')
    for a in q+p:
        if not 2 < a < 2**61 or a % (2*n) != 1 or not is_prime64(a):
            raise ValueError('nonprime_or_invalid_NTT_modulus_or_width')
    sources=[q[i:i+len(p)] for i in range(0,len(q),len(p))]+[p]
    if any(sum(s) >= R64 for s in sources):
        raise ValueError('CRT_uint128_accumulator_range_not_proved')
    # This computes the SAME integer reduction period as the pinned backend.
    # Its safety is then decided by an EXACT integer comparison, not a float.
    for basis in (q,p):
        period=int(float(R64)/float(max(basis))) >> 1
        if period < 2 or 2*period*max(basis) > R64:
            raise ValueError('backend_lazy_accumulation_period_not_certified')
    return True

def digit_bound(block):
    b=math.prod(block)
    # The singleton DecomposeAndSplit branch is integer-only; its >= q>>1
    # convention gives the (q+1)/2 endpoint, not the usual (q-1)/2.
    return F(b+1,2) if len(block)==1 else b*(F(1,2)+crt_delta(len(block)))+F(1,2)

def phase(n,q,p,C,Bs):
    validate(n,q,p)
    P=math.prod(p); m=len(p)
    digits=sum((digit_bound(q[i:i+m]) for i in range(0,len(q),m)),F(0))
    md=(F(1,2)+crt_delta(m)+F(1,2*P))*C*(1+Bs)
    # Encrypting an ordinary Q ciphertext uses ONLY P[0], even for m>1.
    pk=F(20*C*(C+1+Bs),p[0])+(F(1,2)+crt_delta(1)+F(1,2*p[0]))*C*(1+Bs)
    return {'encoding':F(C),'pk':pk,'ks':F(C*40000,P)*digits+md,
            'rescale':F(C*(1+Bs),2),'digit_sum':digits}

def workload(n,active_q,p):
    """Structural counts of multi-P GadgetProduct + ModDown; NOT a clock model.

    NTT limb transforms count both directions equally, no relative cost claim.
    crt_multsum_terms excludes Montgomery reconstruction, additions and scalar
    setup; it is an explicitly named sub-count, not a total operation estimate.
    """
    L=len(active_q); m=len(p); blocks=[active_q[i:i+m] for i in range(0,L,m)]
    b=len(blocks)
    return {'Q_count':L,'P_count':m,'decomposition_blocks':b,
        'block_lengths':[len(x) for x in blocks],
        'gadget_pointwise_products':str(2*n*b*(L+m)),
        'ks_forward_NTT_limbs':str(b*(L+m)+L) if m>=2 else None,
        'ks_inverse_NTT_limbs':str(L+2*m) if m>=2 else None,
        'ks_limb_transforms':str((b+2)*(L+m)) if m>=2 else None,
        'crt_multsum_terms_per_coefficient':str(sum(len(x)*(L-len(x)+m) for x in blocks if len(x)>1)+2*m*L),
        'singleton_decomposition_BRed_calls_per_coefficient':str(sum(L+m for x in blocks if len(x)==1)),
        'scope':'multi-P no-bit GadgetProduct/ModDown; excludes ciphertext tensor, rescale, public correction, setup'}
