import unittest,sys,json,math
from fractions import Fraction as F
from pathlib import Path
import encoding_contract as E
import multiplier_selector as M
import selector as S
import structural_bounds as T

class PublicTests(unittest.TestCase):
    def test_source_hashes(self):self.assertTrue(E.verify_source_hashes())
    def test_ties_even_signed(self):
        self.assertEqual(E.rnd(F(9,8),3),F(1));self.assertEqual(E.rnd(F(11,8),3),F(3,2))
        self.assertEqual(E.rnd(F(-11,8),3),F(-3,2))
    def test_sqrt_rounding(self):
        for p in (128,256,512):
            x=E.sqrt2_rounded(p);s=S.pow2(1-p)
            self.assertLess((x-s/2)**2,2);self.assertGreater((x+s/2)**2,2)
    def test_machin_interval(self):
        a,b=E.pi_interval();self.assertLess(b-a,S.pow2(-1100))
        self.assertLess(F(314159,100000),a);self.assertLess(b,F(314160,100000))
    def test_cosine_actual_recurrence(self):
        # Independent rational Taylor enclosure; no libm decision.
        for p in (128,256,512):
            bound=E.root_error(p);tol=F(bound['cos_truncation'])+F(bound['cos_rounding'])
            m=p//2-1
            for x0 in (F(0),F(1,4),F(1),F(8,5)):
                x=E.rnd(x0,p);s=E.rnd(x*x,p)/4**m
                for _ in range(m):s=E.rnd(s*E.rnd(4-s,p),p)
                actual=E.rnd(1-s/2,p)
                terms=[F((-1)**k)*x**(2*k)/math.factorial(2*k) for k in range(200)]
                a=sum(terms,F(0));b=a+x**400/math.factorial(400)
                self.assertLessEqual(max(abs(actual-a),abs(actual-b)),tol)
    def test_all_current_encoding_bounds(self):
        for m in M.representatives():
            for p in (256,512):
                c=E.certificate(32768,p,m.a,m.b,S.pow2(110))
                self.assertEqual(c['status'],'encoding_bound_le_one')
    def test_low_precision_rejection(self):
        a,b=M.times_unit(1,0,20)
        self.assertEqual(E.certificate(32768,128,a,b,S.pow2(74))['status'],'encoding_bound_not_le_one')
    def test_overlarge_scale_rejection(self):
        self.assertEqual(E.certificate(32768,512,1,0,S.pow2(600))['status'],'encoding_bound_not_le_one')
    def test_wrong_metadata_rejected(self):
        with self.assertRaises(ValueError):E.certificate(32768,512,1,0,F(1,3))
    def test_unsupported_paths(self):
        for n,p in [(100,512),(32768,53),(32768,2048)]:
            with self.assertRaises(ValueError):E.certificate(n,p,1,0,F(1))
    def test_zero_multiplier_rejection(self):
        with self.assertRaises(ValueError):M.Multiplier('zero',0,0)
    def test_small_weight_resolution_rejection(self):
        a,b=M.times_unit(1,0,100)
        with self.assertRaises(ValueError):E.weight_data(a,b,128)
    def test_primitive_gcd_and_norm(self):
        m=M.representatives()[-2];p=m.normalized()
        self.assertEqual((p.a,p.b),(14411518807585600,10190482676041227))
        self.assertEqual(m.norm,25*p.norm)
    def test_primitive_fixed_schedule_dominance(self):
        old=M.representatives()[-2];primitive=old.normalized()
        p=T.scheduled_plan(32768,105,(2,2,2,2));o=S.Oracle(p,S.balanced_p(p.n,p.q,5,170))
        for j in (0,1):self.assertLess(o.error(primitive.weights()[j],j),o.error(old.weights()[j],j))
        self.assertEqual(E.certificate(32768,512,primitive.a,primitive.b,p.scales[0])['status'],'encoding_bound_le_one')
    def test_old_primitive_ordinary_dominance(self):
        m=M.representatives()[-1]
        self.assertGreater(m.a,1);self.assertGreater((m.a-1)**2,2*m.b*m.b)
        p=T.scheduled_plan(32768,105,(2,2,2,2));o=S.Oracle(p,S.balanced_p(p.n,p.q,5,170))
        for j in (0,1):self.assertLess(o.error(F(1),j),o.error(m.weights()[j],j))
    def test_signed_weights(self):
        a,b=M.times_unit(1,0,21);w=E.weight_data(a,b,512)
        self.assertGreater(w[0]['float'],0);self.assertLess(w[1]['float'],0)
        self.assertEqual(a*a-2*b*b,-1)
    def test_unit_oracle_regression(self):
        plan=T.scheduled_plan(32768,74,(1,2,1,1));p=S.balanced_p(plan.n,plan.q,7,330)
        o=S.Oracle(plan,p);m=M.Multiplier('u20',*M.times_unit(1,0,20))
        old=o.record(20);new=M.record(o,m)
        self.assertEqual(new['status'],old['status'])
        self.assertEqual(new['errors_low_high'],old['error_upper_low_high'])
    def test_qp_collision(self):
        plan=T.scheduled_plan(32768,74,(1,2,1,1))
        with self.assertRaises(ValueError):S.Oracle(plan,[plan.q[0]])
    def test_wrong_scale_trajectory(self):
        p=T.scheduled_plan(32768,74,(1,2,1,1))
        altered=S.Plan(p.name,p.n,p.q,p.counts,p.scales[:-1]+(2*p.scales[-1],),p.nominal)
        with self.assertRaises(ValueError):S.Oracle(altered,S.balanced_p(p.n,p.q,7,330))
    def test_error_monotonic_without_independence(self):
        p=T.scheduled_plan(32768,74,(1,2,1,1));o=S.Oracle(p,S.balanced_p(p.n,p.q,7,330))
        es=[o.error(F(i,7)) for i in range(10)]
        self.assertEqual(es,sorted(es))
    def test_go_public_evidence(self):
        path=E.ROOT/'results/go_public_encoding.json'
        self.assertTrue(path.exists(),'run the public Go encoding audit before the full test suite')
        result=json.loads(path.read_text());specs={x['name']:x for x in json.loads((E.ROOT/'validation/encoding_specs.json').read_text())}
        self.assertEqual(F(result['pi']),E.root_error(512)['pi_float'])
        self.assertEqual(F(result['sqrt2']),E.sqrt2_rounded(512))
        for row in result['records']:
            spec=specs[row['name']];a,b=int(spec['a']),int(spec['b'])
            ws=E.weight_data(a,b,512)
            self.assertEqual(row['float_weights'],[str(w['float']) if w['float'].denominator!=1 else str(w['float'].numerator) for w in ws])
            c=E.certificate(int(row['N']),512,a,b,F(row['scale_actual']))
            self.assertLessEqual(F(row['max_coefficient_error']),F(c['coefficient_error_upper']))
    def test_saved_candidate_certificates(self):
        path=E.ROOT/'results/selection_signed/representative_witnesses.json'
        self.assertTrue(path.exists())
        for w in json.loads(path.read_text()):
            if 'certificate' not in w:continue
            d=w['plan'];p=S.Plan(d['id'],int(d['n']),tuple(map(int,d['Q'])),tuple(map(int,d['rescale_counts'])),tuple(map(F,d['actual_scales'])),tuple(map(int,d['nominal_scale_bits'])),F(d['amplitude']))
            m=w['multiplier'];m=M.Multiplier(m['id'],int(m['a']),int(m['b']))
            self.assertEqual(M.record(S.Oracle(p,tuple(map(int,w['P']))),m,True),w['certificate'])

if __name__=='__main__':unittest.main(verbosity=2)
