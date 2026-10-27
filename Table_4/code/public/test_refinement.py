import io
import json
from pathlib import Path
import unittest
from profile_selection import from_matrix,question,scan
from refine_candidates import refine


class RefinementTests(unittest.TestCase):
    def test_frozen_saturated_and_budget_questions(self):
        matrix=json.loads((Path(__file__).resolve().parents[2]/'design/experiment_matrix_v3.json').read_text())
        q=from_matrix(matrix,'C_m32768_b160_r8',16)
        self.assertEqual(q['group_sizes'],[32768]);self.assertEqual(q['dummy_budget'],16)
        with self.assertRaises(ValueError):from_matrix(matrix,'C_m32768_b160_r8',17)

    def test_both_sides_same_rule_and_exact_rebuild(self):
        q=question('refinement_test',[96,32],[8,8]);blocks=[]
        for allocated in (False,True):
            blocks.append(scan(q,allocated,(0,1),[8192],[32],['flat'],[2],[3],[60],io.StringIO()))
        summary={'question':q,'family':{'N':[8192]},'results':blocks}
        log=io.StringIO();result=refine(summary,log)
        self.assertEqual({r['method'] for r in result['results']},{'ordinary','allocated'})
        self.assertTrue(all(r['attempts']==7 for r in result['results']))
        records=[json.loads(s) for s in log.getvalue().splitlines()]
        self.assertTrue(all(not r['security_estimated'] and r['HE_executions']==0 for r in records))
        self.assertEqual(len({tuple(r['branch']['Q']) for r in records}),14)


if __name__=='__main__':unittest.main()
