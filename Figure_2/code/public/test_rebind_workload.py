from copy import deepcopy
import unittest
from rebind_workload import rebind
from profile_selection import question,branch_design,parameter_chain,contract_branch,branch_resources
from selector import allocate_primes


def fixture():
    q=question('C_m1024_b96_r1',[96],[1024])
    Q,counts,nominal,_=parameter_chain(32768,128,4,'flat',2)
    P=allocate_primes(32768,[60]*4,Q)
    b=contract_branch('ordinary_g0',branch_design(q,[0],False),32768,Q,P,counts,128)
    row={'id':'test','branch':b,'resources':branch_resources(b,[1024],False)}
    return {'question':q,'results':[{'method':'ordinary','groups':[0],'fronts_by_N':{'32768':[row]}}]}


class RebindWorkloadTests(unittest.TestCase):
    def test_all_workload_counters_recomputed(self):
        original=fixture();q=question('C_m32768_b96_r1',[96],[32768])
        result=rebind(original,q);a=original['results'][0]['fronts_by_N']['32768'][0]
        b=result['results'][0]['fronts_by_N']['32768'][0]
        self.assertEqual(b['resources']['effective_results'],32768)
        self.assertEqual(b['resources']['batches'],2)
        self.assertEqual(b['resources']['output_bytes'],2*a['resources']['output_bytes'])
        self.assertEqual(b['resources']['relin_bytes'],a['resources']['relin_bytes'])
        self.assertEqual(original['question']['group_sizes'],[1024])

    def test_no_reuse_across_math_or_layout(self):
        for field,value in [('target_bits',[160]),('depth',3),('dummy_ratio',4),('dummy_budget',8)]:
            q=deepcopy(fixture()['question']);q[field]=value
            with self.assertRaises(ValueError):rebind(fixture(),q)

    def test_no_grouped_reuse(self):
        s=fixture();s['results'][0]['groups']=[0,1]
        with self.assertRaises(ValueError):rebind(s,s['question'])


if __name__=='__main__':unittest.main()
