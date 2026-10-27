"""Extension checks for high-precision deep workloads, with no HE execution."""
import json
import unittest

from cost_experiment import ROOT, make_candidate, task, validate_spec


class ExtendedScopeTests(unittest.TestCase):
    def test_original_count_limit_remains_explicit(self):
        t = task('test', 256, 224, 6, 'grow')
        with self.assertRaisesRegex(ValueError, 'Q_count_exceeds_32'):
            make_candidate(t, 1, 0, 65536, 40, 'flat', 2, 2, 60)

    def test_high_precision_chain_is_certified_in_extended_dimension(self):
        t = task('test', 256, 224, 6, 'grow')
        row = make_candidate(t, 1, 0, 131072, 40, 'flat', 2, 2, 60, max_q_limbs=64)
        self.assertGreater(len(row['branch']['Q']), 32)
        self.assertLessEqual(len(row['branch']['Q']), 64)
        self.assertTrue(row['conditional_correctness'], row['reasons'])
        self.assertEqual(row['security_status'], 'not_estimated')

    def test_v1_and_v2_are_distinct_registered_domains(self):
        spec = json.loads((ROOT/'code/design/experiment_matrix.json').read_text())
        validate_spec(spec)
        spec['max_Q_limbs'] = 64
        with self.assertRaises(ValueError):
            validate_spec(spec)
        spec['schema'] = 'pa-fixed-precision-design-v2'
        validate_spec(spec)

    def test_unchanged_domain_matches_original_calibration(self):
        path = ROOT/'raw_data/resume_search_calibration_v1/summary.json'
        if not path.exists():
            self.skipTest('original calibration is local provenance, not a backend dependency')
        summary = json.loads(path.read_text())
        for old in summary['frontier']:
            recipe = old['recipe']
            new = make_candidate(old['task'], old['classes'], old['theta'], old['branch']['N'],
                                 recipe['offset'], recipe['shape'], recipe['slack'],
                                 recipe['P_count'], recipe['P_width'])
            for field in ('id', 'branch', 'group_errors', 'conditional_correctness', 'resources'):
                self.assertEqual(old[field], new[field])


if __name__ == '__main__':
    unittest.main()
