"""Recompute the public error certificate and verify four squarings from retained exact slot-0 values; do not execute homomorphic operations."""
from fractions import Fraction as F
import json
import csv
import math
from pathlib import Path
import sys

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
from profile_certificate import certify

def read(name):
    return json.loads((ROOT/name).read_text())

def z(record):
    return F(record['real']), F(record['imag'])

def add(a,b): return a[0]+b[0], a[1]+b[1]
def sub(a,b): return a[0]-b[0], a[1]-b[1]
def mul(a,b): return a[0]*b[0]-a[1]*b[1], a[0]*b[1]+a[1]*b[0]
def scale(a,x): return a[0]*x,a[1]*x
def norm2(a): return a[0]**2+a[1]**2
def lognorm(a):
    n=norm2(a)
    return None if not n else (math.log2(n.numerator)-math.log2(n.denominator))/2

def main():
    plan=read('code/configurations/slot0_plan.json')
    saved=read('code/configurations/slot0_certificate.json')
    calculated=certify(plan)
    # Saved CLI provenance fields are additional to the mathematical certificate.
    for key,value in calculated.items():
        assert saved[key]==value, f'Certificate mismatch: {key}'
    assert calculated['all_branches_pass']
    branch=calculated['branches'][0]
    values={row['record']:row for row in csv.DictReader((ROOT/'result/source_data/slot0_analysis/slot0_exact_values.csv').open(encoding='utf-8-sig'))}
    weight=F(branch['encoding']['weights'][0]['float_exact'])
    initial_scale=F(branch['encoding']['initial_scale_exact'])
    initial_prediction=scale(add(z(values['fresh_encoding_error']),z(values['fresh_decryption_noise'])),weight/initial_scale)
    initial_difference=sub(z(values['fresh_restored_error']),initial_prediction)
    threshold2=F(1,2**800)
    assert norm2(initial_difference)<=threshold2
    previous=z(values['fresh_restored_error'])
    x=F(3,4)
    rows=[]
    q=list(map(int,plan['contract']['branches'][0]['Q']))
    for i,layer in enumerate(branch['layers'],1):
        tag=f'layer{i}_'
        divisor=F(layer['divisor_exact'])
        delta=F(layer['scale_after_exact'])
        a=F(layer['metadata_rho_exact'])
        previous_scale=F(layer['scale_before_exact'])
        assert a==previous_scale**2/(divisor*delta)
        before,after=layer['Q_before'],layer['Q_after']
        assert divisor==math.prod(q[after:before])
        assert math.prod(q[:before])==divisor*math.prod(q[:after])
        parts={
            'propagated':scale(add(scale(previous,2*x),mul(previous,previous)),a),
            'key_switch_contribution':scale(z(values[tag+'kappa']),weight/(divisor*delta)),
            'rescale_contribution':scale(z(values[tag+'rescale_numerator']),-weight/(divisor*delta)),
            'metadata_contribution':((a-1)*x*x,F(0)),
        }
        prediction=(F(0),F(0))
        for name,value in parts.items():
            assert value==z(values[tag+name]), f'Layer {i}: {name} mismatch'
            prediction=add(prediction,value)
        actual=z(values[tag+'restored_error'])
        residual=sub(actual,prediction)
        assert residual==z(values[tag+'closure_residual'])
        assert scale(actual,1/weight)==z(values[tag+'normalized_residual'])
        assert norm2(residual)<=threshold2
        # Group-zero guarantee must cover this concrete slot.
        assert norm2(actual)<=F(layer['error_upper'][0])**2
        rows.append({'layer':i,'components_exactly_match_saved':True,'closure_log2':lognorm(residual),'within_error_bound':True,'Q_scale_identity_pass':True})
        previous=actual;x=x*x
    assert z(values['final_restored_error'])==previous
    report={'pass':True,'HE_executions':0,'certificate_recomputation_exact_match':True,
            'initial_closure_log2':lognorm(initial_difference),'layers':rows,
            'final_precision_guarantees':{g:r['bits_display'] for g,r in branch['group_errors'].items()},
            'scope':'Recomputes certificate and slot-0 recurrence. The all-slot summary CSV files are preserved observations; this compact package does not independently rescan the omitted full slot arrays.'}
    (ROOT/'result/reproduced').mkdir(exist_ok=True)
    print('Passed: public certificate, initial slot-0 error, four-step error recurrence, and modulus-scale relations. No new homomorphic experiment was run.')

if __name__=='__main__':
    main()
