from copy import deepcopy
from fractions import Fraction as F
import io
import json
import unittest

from group_selection import (prefix_compatible,combined_resources,rebind_groups,
    limited_representatives,prefix_schedules,shared_prefix_candidates)
from profile_selection import question,branch_design,parameter_chain,contract_branch
from profile_certificate import metadata_layers
from selector import allocate_primes


def fixture():
    q=question('group_test',[96,32],[8192,8192])
    primes,counts,nominal,_=parameter_chain(16384,128,4,'flat',2)
    aux=allocate_primes(16384,[60]*3,primes)
    design=branch_design(q,[0],False)
    b=contract_branch('ordinary_g0',design,16384,primes,aux,counts,nominal[0])
    return q,{'id':'anchor','branch':b,'conditional_correctness':True}


class GroupSelectionTests(unittest.TestCase):
    def test_compatible_requires_exact_prefix_N_and_P(self):
        _,a=fixture();a=a['branch'];b=deepcopy(a);b['Q']=b['Q'][:5]
        self.assertTrue(prefix_compatible(a,b))
        b['Q'][0],b['Q'][1]=b['Q'][1],b['Q'][0]
        self.assertFalse(prefix_compatible(a,b))
        b=deepcopy(a);b['N']*=2;self.assertFalse(prefix_compatible(a,b))
        b=deepcopy(a);b['P'].reverse();self.assertFalse(prefix_compatible(a,b))

    def test_shared_payload_no_double_reward(self):
        q,a=fixture();b=deepcopy(a);b['branch']['id']='ordinary_g1';b['branch']['groups']=[1]
        total=combined_resources([b,a],q['group_sizes'])
        self.assertEqual(total['key_family_count'],1)
        self.assertEqual(total['effective_results'],16384)
        self.assertEqual(total['batches'],2)
        self.assertEqual(len(total['security_cases']),1)
        self.assertEqual(total['relin_bytes'],total['key_families'][0]['relin_bytes'])
        b['branch']['P']=list(reversed(b['branch']['P']))
        self.assertEqual(combined_resources([a,b],q['group_sizes'])['key_family_count'],2)

    def test_duplicate_or_missing_business_rejected(self):
        q,a=fixture()
        with self.assertRaises(ValueError):combined_resources([a],q['group_sizes'])
        with self.assertRaises(ValueError):combined_resources([a,a],q['group_sizes'])

    def test_rebind_recomputes_workload_and_accuracy(self):
        q,a=fixture();r=rebind_groups(a,q,[1])
        self.assertEqual(r['branch']['groups'],[1]);self.assertEqual(set(r['group_errors']),{'1'})
        self.assertEqual(r['resources']['effective_results'],8192)
        self.assertTrue(r['conditional_correctness'])

    def test_prefix_schedules_metadata_and_no_fake_security(self):
        q,a=fixture();p=tuple(map(int,a['branch']['Q']))
        candidates=list(prefix_schedules(p,64,4));self.assertTrue(candidates)
        self.assertTrue(any(c[-1]==0 for c in candidates))
        for counts in candidates:
            rows=metadata_layers(p,counts,F(2**64))
            self.assertGreater(rows[-1]['Q_after'],0)
        stream=io.StringIO();r=shared_prefix_candidates(a,q,[1],[32],stream)
        self.assertGreater(r['tested'],0);self.assertGreater(r['conditional_passes'],0)
        for row in map(json.loads,stream.getvalue().splitlines()):
            self.assertFalse(row['security_estimated'])
            self.assertTrue(prefix_compatible(a['branch'],row['branch']))


if __name__=='__main__':unittest.main()
