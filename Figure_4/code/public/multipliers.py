"""Exact cyclotomic-unit construction with enclosing embedding intervals.

Ring: Z[z]/(z**(2*r)+1), r a power of two. No HE or secret keys.
Embedding enclosures use exact rational arithmetic and nested square roots.
mpmath 1.3.0 is used only to propose Fourier exponents, not to certify weights.
Polynomial identities are checked using exact integers.
"""
from fractions import Fraction as F
import hashlib
import json
import math
from functools import lru_cache
import mpmath as mp


def check_r(r):
    if r < 2 or r & (r - 1):
        raise ValueError("r must be a power of two >= 2")


def one(d):
    return (1,) + (0,) * (d - 1)


def monomial(d, exponent):
    quotient, residue = divmod(exponent, d)
    out = [0] * d
    out[residue] = (-1) ** (quotient % 2)
    return tuple(out)


def add(a, b):
    if len(a) != len(b):
        raise ValueError("ring mismatch")
    return tuple(x + y for x, y in zip(a, b))


def mul(a, b):
    if len(a) != len(b):
        raise ValueError("ring mismatch")
    d = len(a)
    out = [0] * d
    for i, x in enumerate(a):
        if not x:
            continue
        for j, y in enumerate(b):
            if y:
                out[(i + j) % d] += x * y * (-1 if i + j >= d else 1)
    return tuple(out)


def power(a, k):
    if k < 0:
        raise ValueError("negative exponent requires explicit inverse")
    result = one(len(a))
    while k:
        if k & 1:
            result = mul(result, a)
        a = mul(a, a)
        k >>= 1
    return result


def galois(a, exponent):
    if math.gcd(exponent, 2 * len(a)) != 1:
        raise ValueError("not a cyclotomic automorphism")
    out = (0,) * len(a)
    for i, x in enumerate(a):
        if x:
            out = add(out, tuple(x * t for t in monomial(len(a), i * exponent)))
    return out


def orbit(r):
    check_r(r)
    d = 2 * r
    v = (0,) * d
    for e in [-2, -1, 0, 1, 2]:
        v = add(v, monomial(d, e))
    factors = [galois(v, pow(5, (-k) % r, 4 * r)) for k in range(r)]
    norm = one(d)
    for a in factors:
        norm = mul(norm, a)
    if any(norm[1:]) or abs(norm[0]) != 1:
        raise ArithmeticError("orbit norm is not a scalar unit")
    inverses = []
    for k in range(r):
        inv = tuple(norm[0] * x for x in one(d))
        for j, a in enumerate(factors):
            if j != k:
                inv = mul(inv, a)
        if mul(factors[k], inv) != one(d):
            raise ArithmeticError("inverse identity failed")
        inverses.append(inv)
    return factors, inverses


def from_exponents(n):
    r = len(n)
    factors, inverses = orbit(r)
    p = inv = one(2 * r)
    for exponent, a, b in zip(n, factors, inverses):
        if exponent < 0:
            a, b = b, a
        p = mul(p, power(a, abs(exponent)))
        inv = mul(inv, power(b, abs(exponent)))
    if mul(p, inv) != one(2 * r) or galois(p, -1) != p:
        raise ArithmeticError("not an exact real unit")
    return p, inv


def quadratic(r, exponent):
    check_r(r)
    d = 2 * r
    h = add(monomial(d, r // 2), tuple(-x for x in monomial(d, 3 * r // 2)))
    u = add(one(d), h)
    inv = add(h, tuple(-x for x in one(d)))
    if mul(u, inv) != one(d):
        raise ArithmeticError("quadratic inverse failed")
    if exponent < 0:
        u, inv = inv, u
    return power(u, abs(exponent)), power(inv, abs(exponent))


def interval_endpoint_to_fraction(t):
    sign, mantissa, exponent, _ = t
    value = F(int(mantissa)) * (F(2) ** int(exponent))
    return -value if sign else value


def interval_round(lo, hi, precision):
    scale = 1 << precision
    lo_scaled, hi_scaled = lo*scale, hi*scale
    return (F(lo_scaled.numerator//lo_scaled.denominator, scale),
            F(-(-hi_scaled.numerator//hi_scaled.denominator), scale))


def sqrt_interval(lo, hi, precision):
    if lo < 0 or hi < lo:
        raise ValueError("invalid square root interval")
    scale = 1 << precision
    low = math.isqrt((lo.numerator*scale*scale)//lo.denominator)
    high = math.isqrt((hi.numerator*scale*scale)//hi.denominator)
    if F(high*high, scale*scale) < hi:
        high += 1
    return F(low, scale), F(high, scale)


def interval_mul(a, b):
    products = [x*y for x in a for y in b]
    return min(products), max(products)


@lru_cache(None)
def cosine_intervals(r, precision):
    """Enclose cos(pi*k/(2*r)) using half-angle and Chebyshev identities."""
    check_r(r)
    c = (F(0), F(0))  # cos(pi/2)
    for _ in range(r.bit_length()-1):
        c = sqrt_interval((1+c[0])/2, (1+c[1])/2, precision)
    values = [(F(1), F(1)), c]
    for k in range(2, r):
        lo,hi = interval_mul(c, values[-1])
        values.append(interval_round(2*lo-values[-2][1],2*hi-values[-2][0],precision))
    values.append((F(0),F(0)))  # cos(pi/2) exactly
    return tuple(values)


def embedding_intervals(p, precision=1024):
    """Exact rational enclosures in the 5**j CKKS ordering, excluding 0."""
    p = tuple(p)
    r = len(p)//2
    check_r(r)
    if galois(p,-1) != p:
        raise ValueError("non-real polynomial")
    cosines = cosine_intervals(r, precision)
    result = []
    for j in range(r):
        a = pow(5,j,4*r)
        lo = hi = F(0)
        for k,coeff in enumerate(p):
            if not coeff:
                continue
            angle = (a*k) % (4*r)
            if angle > 2*r:
                angle = 4*r-angle
            if angle > r:
                angle,coeff = 2*r-angle,-coeff
            left,right = cosines[angle]
            if coeff < 0:
                left,right = right,left
            lo += coeff*left
            hi += coeff*right
        if lo <= 0 <= hi:
            raise ArithmeticError("embedding interval contains zero; increase precision")
        result.append((lo,hi))
    return result


def synthesize(targets, precision=768):
    """Fourier synthesis from a zero-sum logarithmic target vector.

    This small reference DFT is O(r**2); no FFT speed claim is made.
    Acceptance uses actual interval weights in the later certificate.
    """
    r = len(targets)
    check_r(r)
    targets = list(map(F, targets))
    if sum(targets) != 0:
        raise ValueError("log targets must sum to zero")
    with mp.workprec(precision):
        pi = mp.pi
        b = []
        for j in range(r):
            theta = 2 * pi * pow(5, j, 4 * r) / (4 * r)
            b.append(mp.log(abs(mp.sin(5 * theta / 2) / mp.sin(theta / 2)), 2))
        t = [mp.mpf(v.numerator) / v.denominator for v in targets]

        def dft(values, inverse=False):
            sign = 1 if inverse else -1
            return [sum(values[j] * mp.exp(sign * 2j * pi * j * k / r)
                        for j in range(r)) / (r if inverse else 1) for k in range(r)]

        b_hat, t_hat = dft(b), dft(t)
        a_hat = [mp.mpc(0)] + [t_hat[k] / b_hat[k] for k in range(1, r)]
        a = dft(a_hat, inverse=True)
        if max(abs(z.imag) for z in a) > mp.mpf(2) ** (-precision // 2):
            raise ArithmeticError("numerically unresolved real Fourier inverse")
        n = [int(mp.nint(z.real)) for z in a]
        # All-ones changes the unit only by the scalar orbit norm +/-1.
        n = [k - n[-1] for k in n]
    p, inv = from_exponents(n)
    return n, p, inv


def design_profile(bits, precision=1024):
    bits = list(map(F, bits))
    r = len(bits)
    mean = F(sum(bits), r)
    target = [mean - b for b in bits]
    n, p, inv = synthesize(target)
    # Separate higher-precision solve detects sensitivity of exponent rounding.
    n_check, _, _ = synthesize(target, precision=1024)
    if n != n_check:
        raise ArithmeticError("rounded Fourier exponents not stable; inspect tie explicitly")
    ranges = embedding_intervals(p, precision)
    result = {
        "schema": "exact-cyclotomic-profile-v1", "period": r,
        "target_bits": list(map(str, bits)), "mean_target_bits": str(mean),
        "target_log2_weights": list(map(str, target)), "exponents": n,
        "coefficients": list(map(str, p)), "inverse_coefficients": list(map(str, inv)),
        "coefficient_bits": max(abs(x).bit_length() for x in p),
        "embedding_intervals": [{"lower": str(lo), "upper": str(hi)} for lo, hi in ranges],
        "interval_precision_bits": precision,
        "interval_method": "exact rational half-angle square-root bounds and Chebyshev recurrence",
        "inverse_identity_pass": mul(p, inv) == one(2 * r),
        "realness_identity_pass": galois(p, -1) == p,
        "HE_executions": 0,
        "scope": "exact ring identities and interval embeddings only; not an encoder or HE certificate",
    }
    with mp.workprec(256):
        logs = [mp.log(abs(mp.mpf((lo + hi).numerator) / (lo + hi).denominator / 2), 2)
                for lo, hi in ranges]
        result["actual_log2_weights_display"] = [float(x) for x in logs]
        result["max_log2_deviation_display"] = float(max(abs(x - mp.mpf(t.numerator)/t.denominator)
                                                          for x, t in zip(logs, target)))
    encoded = json.dumps(result, sort_keys=True, separators=(",", ":")).encode()
    result["construction_sha256"] = hashlib.sha256(encoded).hexdigest()
    return result


def design_quadratic_profile(bits, exponent, precision=1024):
    """Explicit two-level alternative, including signed units.

    A profile repeated every two positions does not require a general-rank
    Fourier unit. The exponent is a declared candidate, not inferred from HE
    observations or claimed to solve a global parameter optimization problem.
    """
    bits = list(map(int, bits));r = len(bits);check_r(r)
    if any(bits[j] != bits[j % 2] for j in range(r)):
        raise ValueError('quadratic comparison requires an alternating two-level profile')
    p, inv = quadratic(r, exponent)
    ranges = embedding_intervals(p, precision)
    mean = F(sum(bits), r)
    result = {
        'schema':'exact-quadratic-profile-v1','period':r,'target_bits':bits,
        'mean_target_bits':str(mean),'target_log2_weights':[str(mean-b) for b in bits],
        'quadratic_exponent':exponent,'coefficients':list(map(str,p)),
        'inverse_coefficients':list(map(str,inv)),
        'coefficient_bits':max(abs(x).bit_length() for x in p),
        'embedding_intervals':[{'lower':str(lo),'upper':str(hi)} for lo,hi in ranges],
        'interval_precision_bits':precision,
        'inverse_identity_pass':mul(p,inv)==one(2*r),
        'realness_identity_pass':galois(p,-1)==p,'HE_executions':0,
        'scope':'explicit quadratic alternative; complete parameters require recertification',
    }
    result['construction_sha256']=hashlib.sha256(json.dumps(result,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return result
