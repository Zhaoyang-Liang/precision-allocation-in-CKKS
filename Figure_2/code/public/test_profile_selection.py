from fractions import Fraction as F
import io
import json
import unittest

from profile_selection import (partitions,precision_partitions,question,branch_design,
    parameter_chain,branch_resources,contract_branch,pareto,to_go_config,scan)
from selector import allocate_primes


class SelectionTests(unittest.TestCase):
    def test_partitions_complete(self):
        self.assertEqual([len(list(partitions(range(n)))) for n in range(1,5)],[1,2,5,15])
        self.assertEqual(len(precision_partitions([160,32,32,32])),2)
        self.assertEqual(len(precision_partitions([96,80,48,32])),15)

    def test_equal_precision_identity_and_dummy_design(self):
        q=question('equal',[64,64],[8,8])
        d=branch_design(q,[0,1],True)
        self.assertIsNone(d['multiplier']);self.assertEqual(d['slot_pattern'],[])
        q=question('dummy',[160],[8],dummy_ratio=8)
        d=branch_design(q,[0],True)
        self.assertEqual(d['ideal_base'],20);self.assertEqual(d['slot_pattern'],[0]+[-1]*7)

    def test_capacity_not_equal_ring(self):
        q=question('dummy',[160],[8192],dummy_ratio=8)
        d=branch_design(q,[0],True);n=16384
        primes,counts,nominal,_=parameter_chain(n,60,4,'flat',2)
        aux=allocate_primes(n,[60]*3,primes)
        b=contract_branch('allocated',d,n,primes,aux,counts,nominal[0])
        r=branch_resources(b,q['group_sizes'],True)
        self.assertEqual(r['batches'],8);self.assertEqual(r['effective_results'],8192)
        self.assertEqual(r['business_utilization'],'1/8')
        b['slot_pattern']=[];b['multiplier']={'period':1}
        direct=branch_resources(b,q['group_sizes'],False)
        self.assertEqual(direct['batches'],1)
        self.assertEqual(direct['effective_results'],r['effective_results'])

    def test_deferred_terminal_no_unnecessary_rescale(self):
        _,counts,nominal,trajectory=parameter_chain(4096,80,4,'deferred_terminal',2)
        self.assertEqual(counts[-1],0)
        self.assertEqual(nominal[-1],160)
        self.assertEqual(trajectory[-1]['Q_before'],trajectory[-1]['Q_after'])

    def test_scan_and_config_refuses_claims(self):
        q=question('tiny',[96,32],[8,8]);stream=io.StringIO()
        r=scan(q,False,(0,1),[4096],[36],['flat'],[2],[3],[60],stream)
        rows=[json.loads(s) for s in stream.getvalue().splitlines()]
        self.assertEqual(len(rows),1);self.assertFalse(rows[0]['security_estimated'])
        c=to_go_config(q,'ordinary',[rows[0]])
        self.assertEqual(c['certification_status'],'numerical_only')
        self.assertEqual(c['branches'][0]['parameters']['log_n'],12)
        self.assertEqual(pareto(rows*2),rows)


if __name__=='__main__':unittest.main()
