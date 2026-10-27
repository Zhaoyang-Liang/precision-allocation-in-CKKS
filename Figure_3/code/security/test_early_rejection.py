import unittest
from estimate_ranked_candidates import rejection_witness


def attack(bits,passed):
    return {'cost':{'rop':'observed_raw_cost'},'log2_rop':str(bits),'target_pass':passed}


class EarlyRejectionTests(unittest.TestCase):
    def test_one_failed_attack_rejects_but_one_success_never_accepts(self):
        self.assertEqual(rejection_witness({'primal_usvp':attack(127.9,False)}),'primal_usvp')
        self.assertIsNone(rejection_witness({'primal_usvp':attack(128.1,True)}))

    def test_nonfinite_is_not_a_finite_below_target_witness(self):
        self.assertIsNone(rejection_witness({'primal_usvp':attack(float('inf'),False)}))

    def test_missing_raw_cost_or_contradictory_boolean_rejected(self):
        with self.assertRaises(ValueError):rejection_witness({'primal_usvp':attack(90,True)})
        with self.assertRaises(ValueError):rejection_witness({'primal_usvp':{'log2_rop':'90','target_pass':False}})


if __name__=='__main__':unittest.main()
