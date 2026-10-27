"""Conservative small-error lifting bounds for this fixed Lattigo parameter set.

This supplements the recorded integer identities; it does not introduce a
sufficient-recovery-bound stopping rule. All HE classifications stay unchanged.
"""
import argparse
import gzip
import json
import math
from pathlib import Path

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--settings',type=Path,required=True);ap.add_argument('--results',type=Path);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    s=json.loads(args.settings.read_text());N=1<<s['log_n'];Q=s['Q'];P=math.prod(s['P']);E=20
    assert len(s['P'])==2 and s['rescale_count']==2
    blocks=[math.prod(Q[i:i+2]) for i in range(0,len(Q),2)]
    # Both ternary secrets and the ephemeral encryption polynomial have abs<=1.
    # Ignore the helpful P division and bound each component's rounding by 1.
    fresh_bound=E*(2*N+1)+(N+1)
    # DecomposeAndSplit uses centered digits modulo each two-prime product.
    # Four times that product is deliberately looser than the centered bound.
    numerator=4*N*E*sum(blocks)
    kappa_bound=(numerator+P-1)//P+(N+1)
    before_last=math.prod(Q[:s['bottom_prime_count']+s['rescale_count']])
    assert fresh_bound<2**40 and kappa_bound<2**64
    assert 2*fresh_bound<math.prod(Q) and 2*kappa_bound<before_last
    d={'schema':'fixed-parameter-small-error-lifting-bound-v1','N':N,'Gaussian_integer_abs_bound_used':E,
       'fresh_noise_coefficient_bound':fresh_bound,'relinearization_coefficient_bound':kappa_bound,
       'fresh_guard':str(2**40),'relinearization_guard':str(2**64),
       'minimum_Q_before_relinearization':str(before_last),'unique_small_lifts':True,
       'fresh_derivation':'E*(2N+1)+(N+1): bound pk-error times ephemeral ternary polynomial, e0, e1 times ternary secret; allow componentwise modulus-down rounding. Dropping the beneficial P division only enlarges this bound.',
       'relinearization_derivation':'ceil(4*N*E*sum(B_i)/P)+(N+1), where B_i is a two-Q-prime block product. Bound each centered RNS digit by the looser 4*B_i; sum products with bounded evaluation-key errors; account for both component modulus-down remainders.',
       'implementation_scope':['Lattigo v6.2.0 vendored source; uncompressed default relinearization key with two P primes and RNS decomposition','Ternary secret and encryption polynomial, coefficient absolute value at most one','Gaussian sampler configured with absolute bound 19.2; use conservative integer bound 20','DecomposeAndSplit centered CRT digits and ModDownQPtoQ component modulus-down'],
       'source_functions':['core/rlwe/encryptor.go:encryptZeroPk','core/rlwe/keygenerator.go:genEvaluationKey','core/rlwe/evaluator_gadget_product.go:gadgetProductMultiplePLazy','ring/basis_extension.go:DecomposeAndSplit'],
       'not_a_recovery_acceptance_threshold':'These bounds establish small-error lift uniqueness. Failure is still decided from the actual unwrapped restored polynomial, never from these upper bounds.'}
    if args.results:
        families={};max_kappa=0;steps=0;runs=0
        for p in sorted(args.results.glob('r*-*-t*-rep*/result.json')):
            result=json.loads(p.read_text());manifest=json.loads((p.parent/'manifest.json').read_text())
            audit=json.loads((args.results/(p.parent.name+'.audit.json')).read_text());assert audit['pass']
            key=result['key_family_sha256'];noise_hash=manifest['files']['encryption_noise.jsonl.gz']
            if key not in families:
                with gzip.open(p.parent/'encryption_noise.jsonl.gz','rt') as f:noise_max=max(abs(int(json.loads(line)['integer'])) for line in f)
                assert noise_max<=fresh_bound
                families[key]={'noise_file_sha256':noise_hash,'observed_fresh_coefficient_max':noise_max}
            else:assert families[key]['noise_file_sha256']==noise_hash,'paired noise differs'
            for j in range(1,len(result['layers'])):
                step=json.loads((p.parent/f'step_{j:02d}.json').read_text());value=int(step['kappa_coefficient_max']);assert value<=kappa_bound
                max_kappa=max(max_kappa,value);steps+=1
            runs+=1
        d.update(measured_runs_checked=runs,relinearization_steps_checked=steps,observed_kappa_coefficient_max=max_kappa,independent_families=families,paired_noise_hashes_consistent=True)
    args.output.write_text(json.dumps(d,indent=2)+'\n');print(json.dumps({k:d[k] for k in ('fresh_noise_coefficient_bound','relinearization_coefficient_bound','unique_small_lifts')}))

if __name__=='__main__':main()
