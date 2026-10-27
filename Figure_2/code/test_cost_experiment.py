import json
from fractions import Fraction as F
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from cost_experiment import (ROOT, capacity, exact_input, matrix, task, unit,
                             make_candidate, config_for, frontier, boundary_tasks)
from profile_certificate import branch_certificate, certify
from cost_campaign import summarize
from audit_profile_results import exact_input as audit_input


class CostExperimentTests(unittest.TestCase):
    def test_paired_inputs_and_reference_growth(self):
        for seed in (2026101301, 2026101305):
            for i in range(12):
                a = exact_input(seed, 0, i, 'grow')
                b = exact_input(seed, 0, i, 'reciprocal')
                self.assertEqual(a*b, 1)
                self.assertTrue(1 <= a <= 2 and F(1, 2) <= b <= 1)
                self.assertEqual(a, audit_input(seed, 0, i, 'grow'))
                self.assertEqual(b, audit_input(seed, 0, i, 'reciprocal'))
        self.assertEqual(exact_input(1, 0, 1, 'grow')**64, 2**64)
        self.assertEqual(exact_input(1, 0, 1, 'reciprocal')**64, F(1, 2**64))

    def test_capacity_boundary_counts_all_three_types(self):
        for n in (4096, 8192, 65536):
            for r in (1, 2, 4):
                c = n//(2*r)
                for m, batches in ((c-1, 1), (c, 1), (c+1, 2)):
                    v = capacity(n, r, m)
                    self.assertEqual(v['batches'], batches)
                    self.assertEqual(m+v['structural_dummy_slots_total']+v['unused_useful_slots_total'], v['physical_slots_total'])
                self.assertEqual(capacity(n, r, 256)['batches'], 1)

    def test_matrix_is_workload_not_representation(self):
        spec = json.loads((ROOT/'code/design/experiment_matrix.json').read_text())
        tasks = matrix(spec)
        self.assertEqual(len(tasks), 98)
        self.assertEqual(len({t['id'] for t in tasks}), 98)
        self.assertEqual({t['depth'] for t in tasks}, {1, 2, 4, 6})

    def test_zero_transfer_keeps_dummy_capacity(self):
        u = unit(4, 0)
        self.assertEqual(list(map(int, u['coefficients'])), [1]+[0]*7)
        row = make_candidate(task('test', 256, 64, 1, 'grow'), 4, 0, 8192, 32, 'flat', 2, 2, 60)
        cfg = config_for(row, 5)
        self.assertEqual(cfg['branches'][0]['slot_pattern'], [0, -1, -1, -1])
        self.assertEqual(row['capacity']['useful_capacity_per_ciphertext'], 1024)
        self.assertEqual(cfg['repeat'], 5)

    def test_negative_dummy_budget_and_full_ring_gate(self):
        t = task('test', 256, 64, 1, 'grow')
        good = make_candidate(t, 4, 20, 8192, 48, 'flat', 2, 2, 60)
        self.assertEqual(good['nominal_dummy_precision_bits'], -16)
        self.assertTrue(good['conditional_correctness'])
        bad = make_candidate(t, 4, 40, 8192, 32, 'flat', 2, 2, 60)
        self.assertIn('final_full_ring_range_bound_does_not_certify', bad['reasons'])

    def test_amplitude_changes_the_error_bound(self):
        row = make_candidate(task('test', 256, 64, 2, 'grow'), 1, 0, 8192, 48, 'flat', 2, 2, 60)
        b = row['branch']
        growing = branch_certificate(b, 1024, [64], 2, F(2))
        shrinking = branch_certificate(b, 1024, [64], 2, F(1))
        self.assertGreater(F(growing['group_errors']['0']['bound']), F(shrinking['group_errors']['0']['bound']))
        self.assertGreater(F(growing['range_ratios_upper'][0]), F(shrinking['range_ratios_upper'][0]))

    def test_frontier_cannot_erase_other_dimensions_or_transfers(self):
        rows = [make_candidate(task('test', 256, 64, 1, 'grow'), 2, theta, n, 48, 'flat', 2, 2, 60)
                for n in (4096, 8192) for theta in (0, 20)]
        self.assertEqual(len(frontier(rows)), 4)
        self.assertTrue(all(x['messages'] > 0 for x in boundary_tasks(rows[0]['task'], rows)))

    def test_summary_requires_all_five_passes(self):
        rows = [{'repeat': i, 'contract_sha256': 'a', 'question_id': 'task', 'effective_results': 256,
                 'all_checks_pass': True, 'business_accuracy_pass': True, 'wall_ns': 100*i,
                 'error_squared_max_by_group': [str(F(1, 2**(128+i)))]} for i in range(1, 6)]
        self.assertEqual(summarize(rows)['median_wall_ns'], 300)
        with self.assertRaises(ValueError):
            summarize(rows[:4])
        rows[4]['business_accuracy_pass'] = False
        with self.assertRaises(ValueError):
            summarize(rows)

    @unittest.skipUnless(os.environ.get('PA_COST_BINARY'), 'set PA_COST_BINARY for backend integration checks')
    def test_backend_plans_certificates_and_missing_evidence_gate(self):
        binary = os.environ['PA_COST_BINARY']
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            for family in ('grow', 'reciprocal'):
                for k in (1, 6):
                    row = make_candidate(task('test', 256, 64, k, family), 4, 20, 8192, 48, 'flat', 2, 2, 60)
                    cfg = config_for(row, 5)
                    path = temp/f'{family}{k}.json'
                    path.write_text(json.dumps(cfg))
                    plan = temp/f'{family}{k}.plan.json'
                    subprocess.run([binary, '-mode', 'plan', '-config', str(path), '-out', str(plan)], check=True, capture_output=True)
                    data = json.loads(plan.read_text())
                    cert = certify(data)  # Includes exact metadata comparisons for every layer.
                    self.assertEqual(cert['all_branches_pass'], row['conditional_correctness'])
                    self.assertEqual(data['contract']['input_family'], family)
                    out = temp/f'forbidden_{family}{k}'
                    result = subprocess.run([binary, '-mode', 'run', '-config', str(path), '-out', str(out)], capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn(b'lacks security evidence', result.stderr)
                    self.assertFalse(out.exists())


if __name__ == '__main__':
    unittest.main()
