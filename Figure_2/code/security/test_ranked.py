import random
import unittest
from estimate_ranked_candidates import ranked_select
from export_stage_candidates import orders


def fixture(index):
    return {'candidate_id':str(index),'method':'m','resources':{
        'square_Q_words':random.randrange(100),'ks_transform_word_proxy':random.randrange(100),
        'public_correction_words':random.randrange(10),'relin_bytes':random.randrange(100),
        'public_key_bytes':random.randrange(20)},'safe':bool(random.randrange(2))}


class RankedTests(unittest.TestCase):
    def test_prefix_search_equals_full_filter_without_monotonicity(self):
        random.seed(303)
        for _ in range(50):
            rows=[fixture(i) for i in range(30)]
            decisions=ranked_select(rows,lambda r:{'pass':r['safe']})
            for result,key in zip(decisions,orders()[:2]):
                safe=[r for r in rows if r['safe']]
                expected=min(safe,key=key)['candidate_id'] if safe else None
                self.assertEqual(result['selected_candidate_id'],expected)
                ordered=sorted(rows,key=key)
                self.assertEqual([r['candidate_id'] for r in result['visited_prefix']],
                                 [r['candidate_id'] for r in ordered[:len(result['visited_prefix'])]])
                self.assertTrue(all(not r['pass'] for r in result['visited_prefix'][:-1]))

    def test_empty_safe_set_keeps_all_failure_records(self):
        rows=[fixture(i) for i in range(7)]
        results=ranked_select(rows,lambda r:{'pass':False})
        self.assertTrue(all(r['selected_candidate_id'] is None for r in results))
        self.assertTrue(all(len(r['visited_prefix'])==7 for r in results))


if __name__=='__main__':unittest.main()
