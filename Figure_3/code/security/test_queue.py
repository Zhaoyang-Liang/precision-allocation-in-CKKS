import json
from pathlib import Path
import tempfile
import unittest
from prepare_queue import make_union


class QueueTests(unittest.TestCase):
    def test_dedup_exact_parameters_preserves_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            paths=[]
            for i in range(2):
                p=Path(directory)/f'plan{i}.json'
                p.write_text(json.dumps({'branches':[{'id':f'branch{i}',
                    'parameters':{'n':16,'Q':['97'],'P':['193'],'qp_exact':str(97*193)}}]}))
                paths.append(p)
            result=make_union(paths)
            self.assertEqual(len(result['branches']),1)
            self.assertEqual(len(result['branches'][0]['sources']),2)
            self.assertEqual(result['branches'][0]['q_est_log2'],15)
            self.assertFalse(result['security_estimated'])
            self.assertEqual(result['attacks_executed'],0)

    def test_bad_plan_modulus_not_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            p=Path(directory)/'plan.json'
            p.write_text(json.dumps({'branches':[{'id':'broken','parameters':
                {'n':16,'Q':['97'],'P':['193'],'qp_exact':'97'}}]}))
            with self.assertRaises(ValueError):make_union([p])


if __name__=='__main__':unittest.main()
