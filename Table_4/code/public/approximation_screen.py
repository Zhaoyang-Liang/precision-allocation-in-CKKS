"""Exact public function-level challenge; not an HE cost or circuit certificate.

x = 13/16 + t/16, t in [-1,1]. Nonnegative Chebyshev coefficients make
the truncation tail bound exact at t=1. A low polynomial degree alone is NOT
evidence of fewer homomorphic products, rescaling or lower runtime.
"""
import argparse
from fractions import Fraction as F
import json
from pathlib import Path


def chebyshev_power(power):
    coefficients=[F(1)]
    for _ in range(power):
        out=[F(0)]*(len(coefficients)+1)
        for j,c in enumerate(coefficients):
            out[j]+=F(13,16)*c
            if j==0:out[1]+=c/16
            else:out[j-1]+=c/32;out[j+1]+=c/32
        coefficients=out
    assert sum(coefficients,F(0))==F(7,8)**power
    assert sum(((-1)**j*c for j,c in enumerate(coefficients)),F(0))==F(3,4)**power
    return coefficients


def screen(depth,bits):
    c=chebyshev_power(2**depth);budget=F(1,2**(bits+2))
    rows=[]
    for degree in range(len(c)):
        tail=sum(c[degree+1:],F(0))
        # If deg(P)<=degree and ||P-f||<=eps, every omitted Chebyshev
        # coefficient of f is <=2eps by its cosine integral formula.
        lower=max(c[degree+1:],default=F(0))/2
        rows.append({'degree':degree,'truncation_error_exact':str(tail),
                     'arbitrary_polynomial_uniform_error_lower_bound':str(lower),
                     'truncation_fits_quarter_budget':tail<=budget,
                     'any_polynomial_can_meet_total_budget_not_ruled_out':lower<=F(1,2**bits)})
    return {'depth':depth,'target_bits':bits,'input_map':'x=(13+t)/16',
            'coefficients_exact':list(map(str,c)),
            'minimal_certified_truncation_degree':next(r['degree'] for r in rows if r['truncation_fits_quarter_budget']),
            'minimal_truncation_degree_half_budget':next(r['degree'] for r in rows if F(r['truncation_error_exact'])<=F(1,2**(bits+1))),
            'minimal_truncation_degree_full_budget':next(r['degree'] for r in rows if F(r['truncation_error_exact'])<=F(1,2**bits)),
            'polynomial_degree_necessary_lower_bound':next(r['degree'] for r in rows if r['any_polynomial_can_meet_total_budget_not_ruled_out']),
            'candidates':rows,'HE_executions':0,
            'status':'approximation_only_not_a_homomorphic_cost_certificate',
            'unpaid_costs':['input transformation 16*x-13','coefficient representation',
                            'actual evaluation graph','all CKKS arithmetic error and rescaling',
                            'matched security and complete online time']}


if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('matrix');ap.add_argument('out');a=ap.parse_args()
    matrix=json.loads(Path(a.matrix).read_text());pairs=set()
    for q in matrix['questions']:
        for b in q['targets_bits']:pairs.add((q['depth'],b))
    record={'schema':'exact-polynomial-challenge-v1','HE_executions':0,
            'scope':'Exact approximation-only screen, no performance conclusion',
            'rows':[screen(d,b) for d,b in sorted(pairs)]}
    with Path(a.out).open('x') as f:json.dump(record,f,indent=2);f.write('\n')
    for row in record['rows']:
        print(row['depth'],row['target_bits'],row['polynomial_degree_necessary_lower_bound'],row['minimal_certified_truncation_degree'])
