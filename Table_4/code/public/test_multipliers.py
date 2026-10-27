import unittest
from fractions import Fraction as F
import multipliers as m


class ExactConstructionTests(unittest.TestCase):
    def test_square_root_enclosures(self):
        for x in [F(0), F(1), F(2), F(7,13),F(1,2**200)]:
            lo,hi=m.sqrt_interval(x,x,256)
            self.assertLessEqual(lo*lo,x)
            self.assertGreaterEqual(hi*hi,x)
            self.assertLessEqual(hi-lo,F(1,2**256))

    def test_cosine_intervals_against_separate_trig(self):
        import mpmath as mp
        old=mp.iv.prec;mp.iv.prec=512
        try:
            for r in [2,4,8,16]:
                for k,(lo,hi) in enumerate(m.cosine_intervals(r,256)):
                    if k==r: continue # exact zero vs independent numerical pi
                    interval=mp.iv.cos(mp.iv.pi*k/(2*r))
                    a,b=[m.interval_endpoint_to_fraction(t) for t in interval._mpi_]
                    self.assertLessEqual(lo,a)
                    self.assertGreaterEqual(hi,b)
        finally:
            mp.iv.prec=old
    def test_negacyclic_reduction(self):
        for d in (4, 8, 16):
            self.assertEqual(m.monomial(d, -1), tuple(-x for x in m.monomial(d, d-1)))
            self.assertEqual(m.mul(m.monomial(d, d-1), m.monomial(d, 1)), tuple(-x for x in m.one(d)))

    def test_all_orbit_inverses(self):
        for r in (2, 4, 8, 16):
            a, b = m.orbit(r)
            for p, inv in zip(a, b):
                self.assertEqual(m.mul(p, inv), m.one(2*r))

    def test_telescoping(self):
        for r in (2, 4, 8):
            factors, _ = m.orbit(r)
            v = factors[0]
            result = m.one(2*r)
            for h in range(1, r):
                result = m.mul(result, m.galois(v, pow(5, h-1, 4*r)))
                c = (0,) * (2*r)
                for j in range(5**h):
                    c = m.add(c, m.monomial(2*r, j))
                c = m.mul(m.monomial(2*r, (1-5**h)//2), c)
                self.assertEqual(result, c)

    def test_signed_exponents_and_reality(self):
        for n in [(3,-2), (7,-5,2,0), (1,-2,3,-4,5,-6,7,-8)]:
            p, inv = m.from_exponents(n)
            self.assertEqual(m.mul(p, inv), m.one(2*len(n)))
            self.assertEqual(m.galois(p, -1), p)

    def test_quadratic_alternates(self):
        p, _ = m.quadratic(4, -3)
        ranges = m.embedding_intervals(p, 256)
        self.assertTrue(ranges[0][0] > 0)
        self.assertTrue(ranges[1][1] < 0)
        self.assertTrue(max(ranges[0][0], ranges[2][0]) <= min(ranges[0][1], ranges[2][1]))
        self.assertTrue(max(ranges[1][0], ranges[3][0]) <= min(ranges[1][1], ranges[3][1]))

    def test_equal_targets_yield_identity(self):
        n, p, inv = m.synthesize([0,0,0,0])
        self.assertEqual(n, [0]*4)
        self.assertEqual(p, inv)
        self.assertEqual(p, m.one(8))

    def test_reject_nonzero_mean(self):
        with self.assertRaises(ValueError): m.synthesize([1,0])

    def test_profiles_and_exact_inverse(self):
        profiles = [[160,32,32,32], [96,80,48,32], [96,32,96,32], [224]+[0]*7]
        for profile in profiles:
            result = m.design_profile(profile)
            self.assertTrue(result["inverse_identity_pass"])
            self.assertTrue(result["realness_identity_pass"])
            self.assertLess(result["max_log2_deviation_display"], 2*len(profile)-0.5)
            for row in result["embedding_intervals"]:
                lo,hi=F(row["lower"]),F(row["upper"])
                self.assertTrue(lo>0 or hi<0)
                self.assertLess((hi-lo)/min(abs(lo),abs(hi)),F(1,2**256))

    def test_interval_refinement_overlaps(self):
        p,_=m.from_exponents([80,-40,20,0])
        a,b=m.embedding_intervals(p,768),m.embedding_intervals(p,1024)
        for (lo,hi),(lo2,hi2) in zip(a,b):
            self.assertLessEqual(max(lo,lo2),min(hi,hi2))

    def test_fourier_alternating_is_already_quadratic(self):
        result=m.design_profile([96,32,96,32])
        p=tuple(map(int,result['coefficients']))
        self.assertEqual(p,m.quadratic(4,-26)[0])
        # Rounding individual Fourier exponents need not give the closest
        # quadratic exponent. Permit -25 as a separately certified candidate.
        alternative=m.design_quadratic_profile([96,32,96,32],-25)
        self.assertTrue(alternative['inverse_identity_pass'])
        self.assertTrue(alternative['realness_identity_pass'])
        self.assertNotEqual(p,tuple(map(int,alternative['coefficients'])))
        self.assertLess(F(alternative['embedding_intervals'][1]['upper']),0)

    def test_quadratic_cannot_claim_four_levels(self):
        with self.assertRaises(ValueError):m.design_quadratic_profile([96,80,48,32],-25)


if __name__ == "__main__":
    unittest.main()
