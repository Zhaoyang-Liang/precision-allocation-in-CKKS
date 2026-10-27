from copy import deepcopy
from fractions import Fraction as F
import hashlib
import json
import unittest

from multipliers import design_profile
from profile_certificate import (branch_certificate, decoder_bound, metadata_layers,
                                 phase, certify, audited_sources)
from selector import allocate_primes


def branch(mult=None, pattern=None, scale=160):
    n=4096;q=allocate_primes(n,[60]*10);p=allocate_primes(n,[60]*4,q)
    groups=[0] if mult is None else list(range(mult['period']))
    return {'id':'public_test','N':n,'Q':list(map(str,q)),'P':list(map(str,p)),
            'groups':groups,'slot_pattern':pattern or [],'initial_scale_bits':scale,
            'rescale_counts':[3],'output_drop_primes':0,
            'multiplier':mult or {'period':1,'coefficients':['1'],'inverse_coefficients':['1'],
                                  'embedding_intervals':[{'lower':'1','upper':'1'}]}}


class CertificateTests(unittest.TestCase):
    def test_ordinary_cert_and_failure(self):
        b=branch();r=branch_certificate(b,1024,[96],1)
        self.assertTrue(r['pass'],r['reasons'])
        self.assertGreater(F(r['decoder_error_upper']),0)
        self.assertFalse(branch_certificate(b,1024,[224],1)['pass'])

    def test_all_independent_groups_and_dummy(self):
        m=design_profile([160,32,32,32])
        b=branch(m,[0,1,2,3],148)
        r=branch_certificate(b,1024,[160,32,32,32],1)
        self.assertTrue(r['pass'],r['reasons'])
        self.assertEqual(set(r['group_errors']),{'0','1','2','3'})
        b['groups']=[0];b['slot_pattern']=[0,-1,-1,-1]
        d=branch_certificate(b,1024,[160],1)
        self.assertEqual(set(d['group_errors']),{'0'})
        self.assertEqual(d['logical_amplitude_by_residue'][1:],['0']*3)
        # Dummy error remains in the range ledger and follows E^2, not 2AE.
        self.assertEqual(len(d['range_ratios_upper']),4)
        self.assertLess(F(d['layers'][0]['propagated_error'][1]),F(r['layers'][0]['propagated_error'][1]))

    def test_decoder_more_precision_smaller_bound(self):
        vals=[decoder_bound(32768,p,2**190-1,F(2**170)) for p in (512,768,1024)]
        self.assertGreater(vals[0],vals[1]);self.assertGreater(vals[1],vals[2])
        self.assertLess(vals[0],F(1,2**224))

    def test_metadata_retains_high_precision(self):
        b=branch();q=tuple(map(int,b['Q']))
        rows=metadata_layers(q,[1,2,1,2],F(2**150))
        self.assertEqual([r['Q_after'] for r in rows],[9,7,6,4])
        for r in rows:
            self.assertLess(abs(F(r['metadata_rho_exact'])-1),F(1,2**1010))
        with self.assertRaises(ValueError):metadata_layers(q,[10],F(2**150))

    def test_crt_overlap_rejected(self):
        b=branch();q=tuple(map(int,b['Q']))
        with self.assertRaises(ValueError):phase(4096,q,(q[0],))

    def test_sources_match_and_tamper_rejected(self):
        patched={'core/rlwe/scale.go','core/rlwe/metadata.go'}
        self.assertTrue(all(x['inherited_identical'] for x in audited_sources() if x['path'] not in patched))
        io=next(x for x in audited_sources() if x['path']=='core/rlwe/metadata.go')
        self.assertEqual(len(io['sha256']),64)
        self.assertIn('no arithmetic change',io['scope'])
        b=branch()
        c={'depth':1,'precision':1024,'target_bits':[96],'group_sizes':[8],
           'branches':[b],'backend':'github.com/tuneinsight/lattigo/v6@v6.2.0',
           'scale_metadata_bits':1024,'input_interval':['3/4','7/8'],'old_error':'0',
           'input_interface':'native','output_interface':'ordinary_coefficients_high_precision_metadata',
           'algorithm':'direct_square_chain'}
        q=tuple(map(int,b['Q']));trajectory=metadata_layers(q,[3],F(2**160))
        pb={'id':b['id'],'output_Q_count':7,'output_scale_exact':trajectory[-1]['scale_after_exact'],'layers':trajectory}
        sha=hashlib.sha256(json.dumps(c,sort_keys=True,separators=(',',':')).encode()).hexdigest()
        p={'schema':'ckks-profile-public-plan-v1','contract':c,'contract_sha256':sha,'branches':[pb]}
        self.assertTrue(certify(p)['all_branches_pass'])
        corrupted=deepcopy(p);corrupted['contract']['target_bits']=[72]
        with self.assertRaisesRegex(ValueError,'hash'):certify(corrupted)
        corrupted=deepcopy(p);corrupted['branches'][0]['layers'][0]['scale_after_exact']='1'
        with self.assertRaisesRegex(ValueError,'metadata'):certify(corrupted)


if __name__=='__main__':unittest.main()
