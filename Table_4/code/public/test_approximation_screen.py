from fractions import Fraction as F
import unittest
from approximation_screen import chebyshev_power,screen


def evaluate(c,t):
    out=c[0];previous=F(1);current=t
    for j in range(1,len(c)):
        out+=c[j]*current
        previous,current=current,2*t*current-previous
    return out


class ApproximationTests(unittest.TestCase):
    def test_exact_polynomial_identity(self):
        for k in (2,4,8,16):
            c=chebyshev_power(k)
            for t in (F(-1),F(-2,3),F(0),F(1,7),F(1)):
                self.assertEqual(evaluate(c,t),((13+t)/16)**k)

    def test_nonnegative_tail_is_attained(self):
        c=chebyshev_power(16)
        self.assertTrue(all(x>=0 for x in c))
        for degree in (0,4,6,8,15):
            tail=sum(c[degree+1:],F(0))
            self.assertEqual(F(7,8)**16-evaluate(c[:degree+1],F(1)),tail)
            for t in (F(-2,3),F(1,5)):
                self.assertLessEqual(abs(((13+t)/16)**16-evaluate(c[:degree+1],t)),tail)

    def test_not_claiming_an_algorithmic_win(self):
        low=screen(4,22);high=screen(4,160)
        self.assertLess(low['minimal_certified_truncation_degree'],16)
        self.assertEqual(high['polynomial_degree_necessary_lower_bound'],16)
        self.assertEqual(high['HE_executions'],0)
        self.assertEqual(len(high['unpaid_costs']),5)


if __name__=='__main__':unittest.main()
