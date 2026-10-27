import unittest
from fractions import Fraction as F
from multipliers import design_profile
from encoding_profile import certify_encoding, generic_sampled_bounds


class GeneralEncodingTests(unittest.TestCase):
    def test_four_group_profiles(self):
        for targets in [[160,32,32,32],[96,80,48,32],[96,32,96,32]]:
            p=design_profile(targets)
            ranges=[(x['lower'],x['upper']) for x in p['embedding_intervals']]
            c=certify_encoding(32768,1024,list(map(int,p['coefficients'])),ranges,2**120,[F(7,8)]*4)
            self.assertTrue(c['coefficient_error_le_one'])

    def test_dummy_and_large_dimension(self):
        p=design_profile([224]+[0]*7)
        ranges=[(x['lower'],x['upper']) for x in p['embedding_intervals']]
        for n in [4096,8192,16384,32768,65536]:
            c=certify_encoding(n,1024,list(map(int,p['coefficients'])),ranges,2**160,[F(7,8)]+[0]*7)
            self.assertTrue(c['coefficient_error_le_one'])

    def test_ordinary_same_budget(self):
        c=certify_encoding(65536,1024,[1],[(1,1)],2**300,[F(7,8)])
        self.assertTrue(c['coefficient_error_le_one'])

    def test_wrong_weights_not_silently_matched(self):
        p=design_profile([160,32,32,32])
        # Deliberately encode with ideal 1 instead of matching actual embeddings.
        try:
            c=certify_encoding(32768,1024,list(map(int,p['coefficients'])),[(1,1)]*4,2**120,[F(7,8)]*4)
        except ValueError as e:
            self.assertIn('wrong sign',str(e))
        else:
            self.assertFalse(c['coefficient_error_le_one'])

    def test_hoeffding_bounds_all_dimensions(self):
        for n in [4096,8192,16384,32768,65536]:
            v=generic_sampled_bounds(n)
            self.assertEqual(v['secret_polynomials_max'],256)
            self.assertGreaterEqual(v['Bs']**2,2*n*(160+(2*n*256-1).bit_length()))
            self.assertGreaterEqual(v['Be']**2,2*n*400*(160+(2*n*4096-1).bit_length()))


if __name__=='__main__':unittest.main()
