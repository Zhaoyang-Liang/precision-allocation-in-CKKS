import math
import unittest
from estimate_cases import ceil_log2_integer, plan_cases


class SecurityInputTests(unittest.TestCase):
    def test_exact_ceiling(self):
        for b in [10,128,800,1700]:
            self.assertEqual(ceil_log2_integer(1<<b),b)
            self.assertEqual(ceil_log2_integer((1<<b)+1),b+1)
            self.assertEqual(ceil_log2_integer((1<<b)-1),b)

    def test_full_dimension_full_qp(self):
        q=[65537,786433];p=[1179649]
        plan={"branches":[{"id":"b","parameters":{"n":8192,"Q":q,"P":p,"qp_exact":str(math.prod(q+p))}}]}
        row=plan_cases(plan)[0]
        self.assertEqual(row['N'],8192)
        self.assertEqual(row['q_est_log2'],ceil_log2_integer(math.prod(q+p)))
        plan['branches'][0]['parameters']['qp_exact']=str(math.prod(q))
        with self.assertRaises(ValueError):plan_cases(plan)

    def test_overlap_rejected(self):
        plan={"branches":[{"id":"b","parameters":{"n":8192,"Q":[65537],"P":[65537],"qp_exact":str(65537**2)}}]}
        with self.assertRaises(ValueError):plan_cases(plan)


if __name__=='__main__':unittest.main()
