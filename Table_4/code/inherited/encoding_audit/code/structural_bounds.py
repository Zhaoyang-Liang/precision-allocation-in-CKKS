"""Optimistic lower envelope of this square-chain certificate, not actual noise.

All decisions exact. Ignores KS, p0 penalty and actual prime gaps. A rejection
therefore excludes certification under the stated class, not HE correctness.
"""
from fractions import Fraction as F
from functools import lru_cache
import json,argparse
from pathlib import Path
import selector as S

ETA=F(1,2**120)

def compositions(total,length):
    if length==1:
        yield (total,);return
    for x in range(total+1):
        for ys in compositions(total-x,length-1):yield (x,)+ys

def floors(n,depth,amplitude,weights=(F(1),F(1)),targets=(22,72)):
    A=[amplitude**(2**t) for t in range(depth+1)]
    G=[]
    for t in range(depth+1):
        v=F(1)
        for a in A[t:depth]:v*=2*a*(1-ETA)
        G.append(v)
    C=S.cn(n);H=F(C*(1+S.BS[n]),2)
    beta=max(weights[j]*2**targets[j] for j in range(2))
    return [(C+H)*G[0]*beta]+[H*G[t]*beta for t in range(1,depth+1)]

def possible_patterns(n,depth,amplitude,L,weights=(F(1),F(1)),targets=(22,72),maximum=60):
    lower=floors(n,depth,amplitude,weights,targets);possible=[];count=0
    for outL in range(1,L+1):
        for counts in compositions(L-outL,depth):
            count+=1;D=lower[0];Ds=[D]
            for t,r in enumerate(counts):
                D=D*D/(2**(maximum*r)*(1+ETA))
                if r:D=max(D,lower[t+1])
                Ds.append(D)
            if 2*D*amplitude**(2**depth)<2**(maximum*outL):
                possible.append({'counts':[str(x) for x in counts],'output_limbs':str(outL),
                                 'scale_lower':[str(x) for x in Ds]})
    return {'limbs':str(L),'patterns_checked':str(count),'not_excluded_patterns':possible}

def scheduled_plan(n,base,counts,minimum=None,maximum=60,amplitude=F(7,8)):
    minimum=base if minimum is None else minimum
    s=[base];blocks=[]
    for r in counts:
        nxt=max(minimum,2*s[-1]-maximum*r) if r else 2*s[-1]
        total=2*s[-1]-nxt
        if r:
            a,rem=divmod(total,r)
            widths=[a+1]*rem+[a]*(r-rem)
            if not 24<=min(widths)<=max(widths)<=maximum:return None
        else:widths=[]
        blocks.append(widths);s.append(nxt)
    threshold=2*S.pow2(s[-1])*(amplitude**(2**len(counts))+S.pow2(-22))
    final_bits=S.floor_log2(threshold)+1
    widths=S.balanced_widths(final_bits,maximum)
    for block in reversed(blocks):widths+=block
    q=S.allocate_primes(n,widths)
    name=f'n{n.bit_length()-1}_b{base}_floor{minimum}_r'+''.join(map(str,counts))
    return S.Plan(name,n,q,tuple(counts),S.scales_for(q,counts,S.pow2(base)),tuple(s),amplitude)

def main():
    a=argparse.ArgumentParser();a.add_argument('--out',type=Path,required=True);x=a.parse_args()
    if x.out.exists():raise SystemExit('refuse overwrite')
    # Metadata rho envelope for at most 32 divisions and one multiplication.
    u=F(1,2**127)
    assert (1-u)**(-33)<=1+ETA and (1+u)**(-33)>=1-ETA
    results={'scope':'Lower envelope of inherited positive error certificate, Q primes <2^60; not a lower bound on actual CKKS error',
             'metadata_relative_envelope':str(ETA),'families':{}}
    # A rational UNDERestimate of the ideal best beta is enough for exclusion.
    # Ideal unit beta=2^47 for the 72/22 targets, hence exact weights 2^25,2^-25.
    for name,n,weights in [('ordinary_small',16384,(F(1),F(1))),('ordinary',32768,(F(1),F(1))),
                           ('ideal_unit',32768,(F(2**25),F(1,2**25)))]:
        rows=[possible_patterns(n,4,F(7,8),L,weights) for L in range(4,11)]
        results['families'][name]={'n':str(n),'floor_scale_bits_display':[float(S.floor_log2(v)) for v in floors(n,4,F(7,8),weights)],'rows':rows}
    with x.out.open('x') as f:json.dump(results,f,indent=2);f.write('\n')
    for name,r in results['families'].items():
        print(name,[(v['limbs'],len(v['not_excluded_patterns'])) for v in r['rows']])

if __name__=='__main__':main()
