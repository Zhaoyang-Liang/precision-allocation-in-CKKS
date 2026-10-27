"""Native fixed-four-square selector with explicit integer multipliers.

Fair finite local comparison, not global optimization. Coefficient encoding
bound is verified for each input, then uniformly budgeted as <=1 for everyone.
The native path does not require p^-1 modulo Q; that condition is separately
reported for reuse with existing ciphertexts.
"""
from dataclasses import dataclass
from fractions import Fraction as F
from functools import lru_cache
from pathlib import Path
import argparse,json,math
import selector as S
import structural_bounds as T
import encoding_contract as E

@dataclass(frozen=True)
class Multiplier:
    name:str
    a:int
    b:int
    def __post_init__(self):
        if self.a*self.a==2*self.b*self.b:raise ValueError('zero_integer_multiplier')
    @property
    def norm(self):return self.a*self.a-2*self.b*self.b
    def normalized(self):
        g=math.gcd(abs(self.a),abs(self.b))
        return Multiplier(self.name+'_primitive',self.a//g,self.b//g)
    def weights(self):
        return tuple(S.up(w['abs_upper']) for w in E.weight_data(self.a,self.b,512))
    def serial(self):
        return {'id':self.name,'a':str(self.a),'b':str(self.b),
                'subfield_norm':str(self.norm),'coefficient_gcd':str(math.gcd(abs(self.a),abs(self.b))),
                'gamma_bits_display':math.log2(abs(self.norm))/2,
                'weights_abs_upper_low_high':[str(x) for x in self.weights()]}

def times_unit(a,b,k):
    for _ in range(k):a,b=a+2*b,a+b
    return a,b

def representatives():
    # Same finite graphs, scale neighborhood, P counts and P width optimization.
    out=[Multiplier('ordinary',1,0)]
    for name,a,b in [('unit',1,0),('norm2',2,1),('norm7',3,1)]:
        for k in (18,19,20,21,22):out.append(Multiplier(f'{name}_u{k}',*times_unit(a,b,k)))
    out.extend([Multiplier('old_F32_integer',72057594037928000,50952413380206135),
                Multiplier('old_F32_primitive',14411518807585600,10190482676041227)])
    return out

def record(o,m,full=False):
    errors=[];ledgers=[]
    for j,w in enumerate(m.weights()):
        err,ledger=o.error(w,j,True);errors.append(err);ledgers.append(ledger)
    enc=E.certificate(o.plan.n,512,m.a,m.b,o.plan.scales[0],o.plan.amplitude)
    reasons=[]
    if not o.safe:reasons.append('inherited_QP_security_screen_exceeded')
    if enc['status']!='encoding_bound_le_one':reasons.append('native_encoding_bound_not_certified')
    for j,target in enumerate((22,72)):
        if errors[j]>S.pow2(-target):reasons.append(f'group_{j}_error_bound_not_certified')
        if errors[j]>=o.range_cap:reasons.append(f'group_{j}_final_sufficient_range_not_certified')
    r={'status':'conditional_pass' if not reasons else 'not_certified','reasons':reasons,
       'errors_low_high':[str(x) for x in errors],
       'precision_bits_display':[S.display_bits(x) for x in errors],
       'resources':o.resources(0 if m.a==1 and m.b==0 else 1),
       'mod_Q_inverse_exists':math.gcd(m.norm,math.prod(o.plan.q))==1,
       'encoding_excess_bits_display':enc['excess_bits_display'],
       'range_error_cap':str(o.range_cap)}
    if full:r.update(ledgers_low_high=ledgers,encoding_certificate=enc)
    return r

def search_p(plan,m,counts=(3,4,5,7,10)):
    tested=[];boundaries=[]
    for count in counts:
        low=24*count;safe=None;previous=None
        for bits in range(low,60*count+1):
            ps=S.balanced_p(plan.n,plan.q,count,bits)
            S.validate(plan.n,plan.q,ps)
            if previous and not all(a<=b for a,b in zip(previous,ps)):
                raise AssertionError('balanced_P_family_not_componentwise_monotone')
            previous=ps
            if math.prod(plan.q+ps)>=2**S.CAP[plan.n]:break
            safe=bits
        if safe is None:
            boundaries.append({'P_count':str(count),'status':'no_safe_P_in_width_family'});continue
        cache={}
        def check(bits):
            if bits not in cache:
                ps=S.balanced_p(plan.n,plan.q,count,bits);o=S.Oracle(plan,ps)
                r=record(o,m);r.update(P=[str(p) for p in ps],nominal_P_bits=str(bits))
                tested.append(r);cache[bits]=r
            return cache[bits]
        if check(safe)['status']!='conditional_pass':
            boundaries.append({'P_count':str(count),'status':'not_certified_at_largest_safe_P','nominal_P_bits':str(safe)});continue
        a,b=low,safe
        while a<b:
            mid=(a+b)//2
            if check(mid)['status']=='conditional_pass':b=mid
            else:a=mid+1
        first=check(a)
        if a>low:check(a-1)
        # Preserve a modest extra-P margin option as well as the boundary.
        margin=check(min(a+4,safe))
        boundaries.append({'P_count':str(count),'status':'conditional_pass','first_bits':str(a),
                           'first':first,'margin':margin,'largest_safe_bits':str(safe)})
    return {'plan':plan.serial(),'multiplier':m.serial(),'tested':tested,'boundaries':boundaries}

def dominates(a,b):
    # These are separate resource axes, never combined into a time prediction.
    keys=('relin_bytes','public_key_bytes','input_bytes','output_bytes','tensor_work_words','correction_pointwise_words')
    aa=[int(a['certificate']['resources'][k]) for k in keys]
    bb=[int(b['certificate']['resources'][k]) for k in keys]
    for k in ('gadget_pointwise_products','ks_forward_NTT_limbs','ks_inverse_NTT_limbs','crt_multsum_terms_per_coefficient'):
        aa.append(int(a['certificate']['resources']['ks_counts'][k]));bb.append(int(b['certificate']['resources']['ks_counts'][k]))
    return all(x<=y for x,y in zip(aa,bb)) and any(x<y for x,y in zip(aa,bb))

def run(out):
    E.verify_source_hashes()
    if out.exists():raise ValueError('refuse_to_overwrite_results')
    out.mkdir(parents=True)
    reps=representatives();reference=Multiplier('reference',*times_unit(1,0,20))
    beta0=max(w*S.pow2(p) for w,p in zip(reference.weights(),(22,72)))
    allrows=[];witnesses=[];skipped=[]
    for m in reps:
        beta=max(w*S.pow2(p) for w,p in zip(m.weights(),(22,72)))
        ratio=beta/beta0;floor=S.floor_log2(ratio);shift=floor+(ratio>S.pow2(floor))
        center=74+shift
        for base in range(center-1,center+2):
            for counts in ((2,2,2,2),(1,2,1,1),(1,1,2,1)):
                plan=T.scheduled_plan(32768,base,counts)
                if plan is None:
                    skipped.append({'multiplier':m.name,'initial_bits':str(base),'counts':list(map(str,counts)),'reason':'selected_24_to_60_bit_Q_family_cannot_realize_schedule'});continue
                row=search_p(plan,m);allrows.append(row)
                for boundary in row['boundaries']:
                    if boundary['status']!='conditional_pass':continue
                    for tag in ('first','margin'):
                        item=boundary[tag];p=tuple(map(int,item['P']))
                        witnesses.append({'id':m.name+'_'+plan.name+'_p'+boundary['P_count']+'_'+tag,
                                          'multiplier':m.serial(),'plan':plan.serial(),'P':item['P'],
                                          'certificate':record(S.Oracle(plan,p),m,True)})
        print(m.name, 'plans',len(allrows),'passing_witnesses',len(witnesses),flush=True)
    byrep={}
    for m in reps:
        ws=[w for w in witnesses if w['multiplier']['id']==m.name]
        # Duplicated boundary/margin points retain a single canonical witness.
        unique={json.dumps([w['plan']['Q'],w['plan']['actual_scales'],w['P']]):w for w in ws};ws=list(unique.values())
        byrep[m.name]=[w for w in ws if not any(dominates(v,w) for v in ws)]
    output={'scope':'finite native four-square local comparison; no HE; all end-to-end certificates retain inherited key/error/security assumptions',
            'precision':'512','targets_low_high':['22','72'],'multipliers':[m.serial() for m in reps],
            'search_rules':{'scale_offsets':['-1','0','1'],'P_counts':['3','4','5','7','10'],
                           'widths':'24..60 balanced; exact boundary plus 4 total bits',
                           'stop':'declared common local family exhausted; not an optimality proof'},
            'plans':allrows,'unconstructible_cells':skipped,'pareto_per_multiplier':byrep}
    (out/'selector_results.json').write_text(json.dumps(output,indent=2)+'\n')
    best=[]
    for m,ws in byrep.items():
        if not ws:best.append({'multiplier':m,'status':'no_certified_point_in_selected_family'});continue
        w=min(ws,key=lambda w:(int(w['certificate']['resources']['relin_bytes']),int(w['certificate']['resources']['tensor_work_words'])))
        best.append(w)
    (out/'representative_witnesses.json').write_text(json.dumps(best,indent=2)+'\n')
    return output

if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--out',type=Path,required=True);args=ap.parse_args();run(args.out)
