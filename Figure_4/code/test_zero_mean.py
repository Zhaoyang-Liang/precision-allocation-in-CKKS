import unittest
from fractions import Fraction as F
import zero_mean_experiment as z
from multipliers import mul,one
class TestDesign(unittest.TestCase):
 def test_exact_profile_means(self):
  for r in [2,4]:
   for b in [10,0,-10,-20]:
    u=z.unit(r,b);p=list(map(F,u['target_bits']))
    self.assertEqual(sum(p)/r,b);self.assertEqual(p[0],20)
    self.assertEqual(mul(tuple(map(int,u['coefficients'])),tuple(map(int,u['inverse_coefficients']))),one(2*r))
 def test_low_scales_are_not_clamped(self):
  t=next(t for t in z.tasks() if t['classes']==4 and t['nominal_mean_bits']==-20 and t['depth']==0)
  self.assertEqual(z.settings(t,40)['scale_bits'],8)
 def test_deferred_rescale(self):
  blocks,scales=z.schedule(8,4)
  self.assertEqual(blocks,[[],[24],[],[24]]);self.assertEqual(scales,[8,16,8,16,8])
 def test_public_initial_20bit_certificates(self):
  for t in z.tasks()[:9]:
   result,_=z.public_check(t,z.settings(t,80),z.unit(t['classes'],t['nominal_mean_bits']))
   self.assertTrue(result['public_sufficient_certificate_pass'],t['id'])
if __name__=='__main__':unittest.main()
