"""Synthetic schema tests only; these fixtures are never formal security files."""
from copy import deepcopy
import json
from pathlib import Path
import tempfile
import unittest
from estimate_cases import reusable_estimates


def fixture():
    attacks={k:{'cost':{'rop':'1.2676506002282294e30'},'log2_rop':'100',
                'target_pass':False,'wall_seconds':0} for k in ('primal_usvp','primal_bdd','dual_hybrid')}
    return {'schema':'ckks-new-security-v1','estimator_commit':'a'*40,'estimator_tracked_dirty':[],
            'wrapper_sha256':'b'*64,'model':'RC.MATZOV','secret':'uniform_ternary',
            'error_sigma':'3.2','actual_sampler_abs_bound':'19.2','samples':'infinity','target_bits':128,
            'cases':[{'branch':'fixture','N':16,'Q':['97'],'P':['193'],'qp_exact':str(97*193),
                      'q_est_log2':15,'attacks':attacks,'all_three_attacks_pass':False}]}


class ReuseTests(unittest.TestCase):
    def apply(self,data):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'fixture.json';p.write_text(json.dumps(data))
            return reusable_estimates([p],'a'*40,128)

    def test_exact_input_only_no_interpolation(self):
        cache,provenance=self.apply(fixture())
        self.assertIn((16,15),cache);self.assertNotIn((16,14),cache)
        self.assertEqual(len(provenance[0]['sha256']),64)
        self.assertFalse(cache[(16,15)]['attacks']['dual_hybrid']['target_pass'])

    def test_incomplete_rejected(self):
        d=fixture();del d['cases'][0]['attacks']['primal_bdd']
        with self.assertRaises(ValueError):self.apply(d)

    def test_legacy_infinity_is_preserved_but_not_accepted(self):
        d=fixture();a=d['cases'][0]['attacks']['primal_usvp']
        a['log2_rop']='+infinity';a['cost']['rop']='+infinity';a['target_pass']=True
        cache,_=self.apply(d)
        normalized=cache[(16,15)]['attacks']['primal_usvp']
        self.assertEqual(normalized['log2_rop'],'+infinity')
        self.assertFalse(normalized['target_pass'])

    def test_model_and_version_rejected(self):
        for key,value in [('model','other'),('estimator_commit','c'*40),('target_bits',100),('samples','finite')]:
            d=fixture();d[key]=value
            with self.assertRaises(ValueError):self.apply(d)

    def test_modulus_and_pass_forgery_rejected(self):
        for field,value in [('qp_exact','97'),('q_est_log2',14),('all_three_attacks_pass',True)]:
            d=fixture();d['cases'][0][field]=value
            with self.assertRaises(ValueError):self.apply(d)


if __name__=='__main__':unittest.main()
