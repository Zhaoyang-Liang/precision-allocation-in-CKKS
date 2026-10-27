"""Public, conditional correctness certificate for the NEW direct-square runner.

No security attack or HE is run here. A failed bound is not an impossibility
result. The actual Q/P security estimator evidence is a separate mandatory gate.
The coefficient encoder budget is one for BOTH representations.
"""
import argparse
from fractions import Fraction as F
from functools import lru_cache
import hashlib
import json
import math
from pathlib import Path

from encoding_profile import (certify_encoding, generic_sampled_bounds,
                              root_error, upper, INHERITED)
from selector import round_binary, pow2
from multip_contract import validate, crt_delta, digit_bound, workload
from certify import cn

ROOT = Path(__file__).resolve().parents[1]
WB = 768


def up(x):
    return upper(x, WB)


@lru_cache(None)
def _encoding_cached(n, precision, coefficients, intervals, scale, amplitudes):
    return certify_encoding(n,precision,list(coefficients),intervals,scale,amplitudes)


def bits_display(x):
    return None if not x else math.log2(x.denominator)-math.log2(x.numerator)


@lru_cache(None)
def audited_sources():
    """Check the inherited FFT/root source against the code actually compiled."""
    manifest=json.loads((INHERITED.parent/'reference/source_contract.json').read_text())
    vendor=ROOT/'engine/vendor/github.com/tuneinsight/lattigo/v6'
    rows=[]
    for item in manifest['files']:
        path=vendor/item['path']
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        if item['path'] != 'core/rlwe/scale.go' and digest != item['sha256']:
            raise ValueError('inherited encoding source mismatch: '+item['path'])
        rows.append({'path':item['path'],'sha256':digest,
                     'inherited_identical':digest==item['sha256']})
    # Metadata framing is outside numerical encoding/evaluation, but must also
    # be versioned: decimal scale exponents can exceed the old two-digit field.
    io_path=vendor/'core/rlwe/metadata.go'
    rows.append({'path':'core/rlwe/metadata.go','sha256':hashlib.sha256(io_path.read_bytes()).hexdigest(),
                 'inherited_identical':False,'scope':'variable-exponent JSON framing; no arithmetic change; public wire tests required'})
    # Scale is separately patched to 1024 for BOTH methods; record its hash.
    return rows


@lru_cache(None)
def phase(n, q, p):
    validate(n,q,p)
    C=cn(n); event=generic_sampled_bounds(n)
    Bs,Be=event['Bs'],event['Be']; P=math.prod(p); m=len(p)
    digits=sum((digit_bound(q[i:i+m]) for i in range(0,len(q),m)),F(0))
    md=(F(1,2)+crt_delta(m)+F(1,2*P))*C*(1+Bs)
    pk=F(20*C*(C+1+Bs),p[0])+(F(1,2)+crt_delta(1)+F(1,2*p[0]))*C*(1+Bs)
    return {'encoding':F(C),'pk':up(pk),
            'ks':up(F(C*Be,P)*digits+md),'rescale':F(C*(1+Bs),2)}


def metadata_layers(q, counts, initial):
    """Exact emulation of 1024-bit nearest-even big.Float metadata operations."""
    D=F(initial); L=len(q); rows=[]
    for t,count in enumerate(counts):
        if count<0 or count>=L:
            raise ValueError('rescale exhausts Q')
        old=D; deleted=q[L-count:L] if count else ()
        D=round_binary(D*D,1024)
        for prime in reversed(deleted):
            D=round_binary(D/prime,1024)
        div=math.prod(deleted)
        rows.append({'layer':t+1,'Q_before':L,'Q_after':L-count,
                     'scale_before_exact':str(old),'scale_after_exact':str(D),
                     'divisor_exact':str(div),
                     'metadata_rho_exact':str(old*old/(div*D))})
        L-=count
    return rows


@lru_cache(None)
def decoder_bound(n, precision, Q, scale):
    """Deterministic full-slot decoder error, including CRT integer conversion.

    The backend's >= floor(Q/2) centering requires (Q+1)/2, not (Q-1)/2.
    SetInt + Quo each round at the configured precision. Each FFT butterfly
    has component norm <=4; beta additionally covers roots and three rounded
    arithmetic stages. Complex magnitude <= twice the component bound.
    No final optional DecodePublic rounding is invoked (logprec=0).
    Scale round-trip equality is checked separately by the runner.
    """
    if precision not in (512,768,1024) or scale<=0 or n&(n-1):
        raise ValueError('decoder outside contract')
    u=pow2(1-precision); A=F(Q+1,2)/scale
    B=up(A*(1+u)**2); E=up(A*(2*u+u*u))
    beta=up(4*(1+root_error(precision)['root_component_error'])*(1+u)**3)
    for _ in range((n//2).bit_length()-1):
        E=up(4*E+(beta-4)*B); B=up(beta*B)
    return up(2*E)


def branch_certificate(branch, precision, targets, depth, input_amplitude=F(7,8)):
    """branch uses contract keys; groups identify global independent businesses."""
    n=int(branch['N']);q=tuple(map(int,branch['Q']));p=tuple(map(int,branch['P']))
    validate(n,q,p)
    mult=branch['multiplier'];coefs=list(map(int,mult['coefficients']))
    pattern=branch['slot_pattern'];groups=branch['groups'];r=mult['period']
    if r==1:
        if coefs!=[1] or mult['inverse_coefficients']!=['1']:
            raise ValueError('ordinary contract mismatch')
        if pattern:
            raise ValueError('ordinary branch must use compact packing')
        slot_groups=[tuple(groups)]
        amps=[F(input_amplitude)]
    else:
        if len(pattern)!=r or len(coefs)!=2*r or n%len(coefs):
            raise ValueError('subring/layout mismatch')
        from multipliers import mul, one
        if mul(coefs,list(map(int,mult['inverse_coefficients']))) != one(len(coefs)):
            raise ValueError('invalid exact inverse')
        slot_groups=[() if g==-1 else (g,) for g in pattern]
        amps=[F(input_amplitude) if gs else F(0) for gs in slot_groups]
    intervals=[(F(x['lower']),F(x['upper'])) for x in mult['embedding_intervals']]
    D=pow2(branch['initial_scale_bits'])
    encoding=_encoding_cached(n,precision,tuple(coefs),tuple(intervals),D,tuple(amps))
    w=[F(row['abs_upper']) for row in encoding['weights']]
    if len(w)!=len(amps):raise ValueError('weight shape')
    counts=branch['rescale_counts']
    if len(counts)!=depth:raise ValueError('depth mismatch')
    trajectory=metadata_layers(q,counts,D)
    ph=phase(n,q,p)
    E=[up(weight*(ph['encoding']+ph['pk'])/D) for weight in w]
    initial=list(E); A=list(amps);L=len(q);layers=[]
    for t,row in enumerate(trajectory):
        ph=phase(n,q[:L],p); count=counts[t]
        deleted=q[L-count:L] if count else ()
        nextD=F(row['scale_after_exact']);divisor=int(row['divisor_exact'])
        rho=F(row['metadata_rho_exact']); R=F(0)
        for prime in reversed(deleted):R=R/prime+1
        old=[up(abs(rho)*(2*a*e+e*e)) for a,e in zip(A,E)]
        ks=[up(weight*ph['ks']/(divisor*nextD)) for weight in w]
        rs=[up(weight*ph['rescale']*R/nextD) for weight in w]
        meta=[up(abs(rho-1)*a*a) for a in A]
        E=[up(sum(xs,F(0))) for xs in zip(old,ks,rs,meta)]
        layers.append({**row,'propagated_error':list(map(str,old)),
                       'KS_ModDown_error':list(map(str,ks)),
                       'rescale_error':list(map(str,rs)),
                       'metadata_error':list(map(str,meta)),
                       'error_upper':list(map(str,E)),
                       'work':workload(n,q[:L],p)})
        L-=count;D=nextD;A=[a*a for a in A]
    L-=branch['output_drop_primes']
    if L<1:raise ValueError('final Q exhausted')
    Q=math.prod(q[:L]); observer=decoder_bound(n,precision,Q,D)
    final=[up(e+observer) for e in E]
    # Both decoder branches recenter the endpoint floor(Q/2) as negative.
    # Strictly stay below (Q-1)/2; do not silently use the symmetric Q/2 rule.
    ranges=[up(2*D*(a+e)/(Q-1)) for a,e in zip(A,E)]
    reasons=[]
    if not encoding['coefficient_error_le_one']:reasons.append('encoding_coefficient_bound_exceeds_one')
    group_errors={}
    for gs,e in zip(slot_groups,final):
        for g in gs:
            group_errors[g]=max(group_errors.get(g,F(0)),e)
    if set(group_errors)!=set(groups):raise ValueError('missing assigned groups')
    for g,e in group_errors.items():
        if e>pow2(-targets[g]):reasons.append(f'group_{g}_current_error_bound_does_not_certify')
    if max(ranges)>=1:reasons.append('final_full_ring_range_bound_does_not_certify')
    return {'id':branch['id'],'pass':not reasons,'reasons':reasons,
            'N':n,'Q':list(map(str,q)),'P':list(map(str,p)),
            'encoding':encoding,'sampled_event':generic_sampled_bounds(n),
            'initial_error_upper':list(map(str,initial)),
            'weight_upper':list(map(str,w)), 'logical_amplitude_by_residue':list(map(str,amps)),
            'layers':layers,'decoder_error_upper':str(observer),
            'final_logical_error_upper':list(map(str,E)),
            'final_observed_error_upper':list(map(str,final)),
            'group_errors':{str(g):{'bound':str(e),'bits_display':bits_display(e),'target':targets[g]}
                            for g,e in group_errors.items()},
            'range_ratios_upper':list(map(str,ranges)),
            'output_Q_count':L,'output_scale_exact':str(D),
            'dummy_errors_are_not_business_targets':True}


def certify(plan):
    if plan['schema']!='ckks-profile-public-plan-v1':raise ValueError('plan schema')
    contract=plan['contract']
    encoded=json.dumps(contract,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()
    if hashlib.sha256(encoded).hexdigest()!=plan['contract_sha256']:
        raise ValueError('contract hash mismatch')
    families={'grow':['1','2'],'reciprocal':['1/2','1']}
    family=contract.get('input_family')
    if family is not None and family not in families:raise ValueError('unknown input family')
    interval=families[family] if family else ['3/4','7/8']
    expected={'backend':'github.com/tuneinsight/lattigo/v6@v6.2.0','scale_metadata_bits':1024,
              'input_interval':interval,'old_error':'0','input_interface':'native',
              'output_interface':'ordinary_coefficients_high_precision_metadata','algorithm':'direct_square_chain'}
    for k,v in expected.items():
        if contract[k]!=v:raise ValueError('unsupported contract '+k)
    sources=audited_sources()
    rows=[branch_certificate(b,contract['precision'],contract['target_bits'],contract['depth'],F(interval[1]))
          for b in contract['branches']]
    for b,pb in zip(rows,plan['branches'],strict=True):
        if b['id']!=pb['id'] or b['output_scale_exact']!=pb['output_scale_exact'] or b['output_Q_count']!=pb['output_Q_count']:
            raise ValueError('actual backend output plan mismatch')
        for calculated,actual in zip(b['layers'],pb['layers'],strict=True):
            for k in ('Q_before','Q_after','scale_before_exact','scale_after_exact','divisor_exact','metadata_rho_exact'):
                if calculated[k]!=actual[k]:raise ValueError('actual metadata mismatch '+k)
    return {'schema':'ckks-profile-certificate-v1','contract_sha256':plan['contract_sha256'],
            'all_branches_pass':all(r['pass'] for r in rows),'branches':rows,
            'decoder_bound_included':True,'source_files':sources,'HE_executions':0,
            'security_estimated':False,'unconditional_claim':False,
            'scope':'Fixed direct-square graph; conditional on stated backend floating/CRT model and sampled-key event. Failure is not infeasibility.',
            'assumptions':['Pinned 64-bit Lattigo v6.2.0 guarded CRT implementation, no extra gadget bit decomposition.',
                           'Nearest-even big.Float/root/IFFT/FFT implementation at declared precision; exact scale round-trip checked at runtime.',
                           'Independent centered coefficients only within freshly sampled polynomials; no independence of adaptive digits and key errors.',
                           'At most 256 secret-type and 4096 error-type polynomials per ring dimension per configuration, checked by runner; V3 saturated-batch envelope.',
                           'Separate full-QP RC.MATZOV lattice-estimator gate before any HE run.']}


if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('plan');a.add_argument('out');v=a.parse_args()
    p=Path(v.plan);r=certify(json.loads(p.read_text()))
    r['plan_sha256']=hashlib.sha256(p.read_bytes()).hexdigest()
    r['certificate_program_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with Path(v.out).open('x') as f:json.dump(r,f,indent=2);f.write('\n')
    print('conditional correctness:',r['all_branches_pass'],'(no security estimate or HE)')
