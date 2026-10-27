"""Extend the inherited encoder ledger to explicitly bounded real multipliers.

The original FFT/root/final-rounding bounds are reused, not re-inferred from
measured RMS. New weights are certified by exact rational cyclotomic intervals.
The concrete Go input path must divide by the specified rounded midpoint.
"""
from fractions import Fraction as F
from pathlib import Path
import sys
import math

INHERITED = Path(__file__).resolve().parent / "dependencies/code"
sys.path.insert(0, str(INHERITED))
from encoding_contract import root_error, upper, rnd
from selector import pow2
from multipliers import embedding_intervals


def certify_encoding(n, precision, coefficients, supplied_ranges, scale, amplitudes):
    """All inputs public; amplitudes indexed by slot residue, zeros for dummy."""
    if n < 16 or n & (n-1) or n % len(coefficients):
        raise ValueError("ring/subring mismatch")
    if precision not in (512, 768, 1024):
        raise ValueError("outside numerical encoder contract")
    scale = F(scale)
    if scale <= 0 or rnd(scale,1024) != scale:
        raise ValueError("initial metadata is not exact at 1024 bits")
    if len(coefficients)==1:
        if coefficients != [1]:
            raise ValueError("scalar-only interface currently p=1")
        actual = [(F(1),F(1))]
    else:
        actual = embedding_intervals(coefficients, precision+256)
    if len(actual)!=len(supplied_ranges) or len(actual)!=len(amplitudes):
        raise ValueError("weight and amplitude dimensions")
    roots = root_error(precision)
    u = pow2(1-precision)
    wb = precision+192
    zeta = Z = F(0)
    weights = []
    for (lo,hi),(slo,shi),amp in zip(actual,supplied_ranges,amplitudes):
        slo,shi,amp=F(slo),F(shi),F(amp)
        if slo>shi or slo*shi<=0 or amp<0:
            raise ValueError("invalid supplied weight or amplitude")
        wf=rnd((slo+shi)/2,precision)
        if not wf or (wf>0)!=(lo>0):
            raise ValueError("rounded midpoint has wrong sign")
        tau=max(abs(wf-lo),abs(wf-hi))
        small=min(abs(lo),abs(hi));large=max(abs(lo),abs(hi))
        weights.append({"float_exact":str(wf),"abs_lower":str(small),"abs_upper":str(large),"weight_error_upper":str(tau)})
        zeta=max(zeta,amp*((2*u+u*u)/abs(wf)+tau/(small*abs(wf))))
        Z=max(Z,amp*(1+u)**2/abs(wf))
    zeta,Z=upper(zeta,wb),upper(Z,wb)
    beta=upper(4*(1+roots['root_component_error'])*(1+u)**3,wb)
    E,B=zeta,Z
    slots=n//2
    for _ in range(slots.bit_length()-1):
        E=upper(4*E+(beta-4)*B,wb)
        B=upper(beta*B,wb)
    E,B=upper(E/slots,wb),upper(B/slots,wb)
    float_round=upper((2*u+u*u)*scale*B+u/2,wb)
    total=F(1,2)+upper(scale*E+float_round,wb)
    return {"schema":"general-real-multiplier-encoder-ledger-v1","N":n,
            "precision":precision,"initial_scale_exact":str(scale),
            "coefficient_error_upper":str(total),"coefficient_error_le_one":total<=1,
            "input_component_error_upper":str(zeta),"IFFT_component_error_upper":str(E),
            "final_float_rounding_upper":str(float_round),"weights":weights,
            "scope":"inherited Lattigo v6.2.0 big.Float input/FFT/rounding path with midpoint weights; no HE error or decoder guarantee",
            "weight_enclosure":"exact rational nested radicals", "HE_executions":0}


def generic_sampled_bounds(n, failure_bits=160, secret_polynomials=256, error_polynomials=4096):
    """Conservative coefficientwise Hoeffding + union bound, all dimensions.

    For independent mean-zero coefficients bounded by a, each complex canonical
    coordinate exceeds B with probability <=4 exp(-B^2/(2*N*a^2)). Union over
    N/2 coordinates and F sampled polynomials gives 2*N*F times this exponential.
    Using ln(2)<1 avoids numerical decision logs. No independence is required
    between ciphertext digits and the sampled evaluation-key errors.
    """
    if n<16 or n&(n-1): raise ValueError("power-of-two ring")
    def ceiling_sqrt(x):
        z=math.isqrt(x)
        return z+(z*z<x)
    def log2_ceil_int(x):return (x-1).bit_length()
    bs=ceiling_sqrt(2*n*(failure_bits+log2_ceil_int(2*n*secret_polynomials)))
    be=ceiling_sqrt(2*n*400*(failure_bits+log2_ceil_int(2*n*error_polynomials)))
    return {"Bs":bs,"Be":be,"secret_polynomials_max":secret_polynomials,
            "error_polynomials_max":error_polynomials,"coefficient_error_abs_bound":20,
            "failure_probability_per_dimension_upper":f"2^-{failure_bits-1}",
            "scope":"joint event for sampled centered independent-coefficient polynomials; enforce family counts in runner"}
