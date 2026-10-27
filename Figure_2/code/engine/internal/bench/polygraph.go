package bench

// The official polynomial scheduler is reused with a metadata-only adapter.
// Execution mode delegates arithmetic and verifies every output metadata tuple.
// Immutable node versions preserve dependencies across in-place calls.
import (
	"fmt"
	cp "github.com/tuneinsight/lattigo/v6/circuits/ckks/polynomial"
	common "github.com/tuneinsight/lattigo/v6/circuits/common/polynomial"
	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/schemes"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	"github.com/tuneinsight/lattigo/v6/utils/bignum"
	"math/big"
	"reflect"
	"weak"
)

type GraphState struct {
	Level  int    `json:"level"`
	Degree int    `json:"degree"`
	Scale  string `json:"scale_exact"`
}
type GraphNode struct {
	ImplicitScalarMultiplications int        `json:"internal_scale_alignment_scalar_multiplications"`
	ID                            int        `json:"id"`
	Op                            string     `json:"op"`
	Inputs                        []int      `json:"inputs"`
	State                         GraphState `json:"state"`
	Factor                        string     `json:"factor_exact,omitempty"`
	AccFactor                     string     `json:"accumulator_factor_exact,omitempty"`
	Constant                      string     `json:"constant_exact,omitempty"`
	Scalar                        string     `json:"ideal_scalar_exact,omitempty"`
	Relin                         bool       `json:"relinearization"`
	Primes                        []string   `json:"removed_primes,omitempty"`
}
type PolynomialGraph struct {
	Nodes   []GraphNode `json:"nodes"`
	Output  int         `json:"output_node"`
	Backend string      `json:"backend"`
	Scope   string      `json:"scope"`
}
type graphRef struct {
	p  weak.Pointer[rlwe.Ciphertext]
	id int
}
type graphEvaluator struct {
	*ckks.Evaluator
	params   ckks.Parameters
	delegate schemes.Evaluator
	refs     map[uintptr]graphRef
	graph    PolynomialGraph
}

func graphState(c *rlwe.Ciphertext) GraphState {
	return GraphState{c.Level(), c.Degree(), scaleRat(c.Scale).RatString()}
}
func newGraphEvaluator(p ckks.Parameters, e *ckks.Evaluator, d schemes.Evaluator) *graphEvaluator {
	return &graphEvaluator{Evaluator: e, params: p, delegate: d, refs: map[uintptr]graphRef{}, graph: PolynomialGraph{Backend: Backend, Scope: "official scheduler; exact public metadata/scalar model; no secret data"}}
}
func (e *graphEvaluator) bind(c *rlwe.Ciphertext, id int) {
	e.refs[reflect.ValueOf(c).Pointer()] = graphRef{weak.Make(c), id}
}
func (e *graphEvaluator) append(c *rlwe.Ciphertext, n GraphNode) int {
	n.ID = len(e.graph.Nodes)
	n.State = graphState(c)
	e.graph.Nodes = append(e.graph.Nodes, n)
	e.bind(c, n.ID)
	return n.ID
}
func (e *graphEvaluator) root(c *rlwe.Ciphertext) { e.append(c, GraphNode{Op: "input"}) }
func (e *graphEvaluator) id(c *rlwe.Ciphertext) (int, error) {
	if r, ok := e.refs[reflect.ValueOf(c).Pointer()]; ok && r.p.Value() == c {
		old := e.graph.Nodes[r.id].State
		now := graphState(c)
		if old != now {
			if old.Degree != now.Degree || now.Level > old.Level {
				return 0, fmt.Errorf("untracked degree/level mutation")
			}
			a, _ := new(big.Rat).SetString(old.Scale)
			b, _ := new(big.Rat).SetString(now.Scale)
			return e.append(c, GraphNode{Op: "metadata", Inputs: []int{r.id}, Factor: div(a, b).RatString()}), nil
		}
		return r.id, nil
	}
	// The official evaluator creates zero accumulators outside its interface.
	// An unregistered nonzero operand is rejected, never silently called zero.
	for _, p := range c.Value {
		for _, limb := range p.Coeffs {
			for _, x := range limb {
				if x != 0 {
					return 0, fmt.Errorf("unregistered nonzero polynomial operand")
				}
			}
		}
	}
	return e.append(c, GraphNode{Op: "zero"}), nil
}
func scalarOriginal(v rlwe.Operand) (*big.Rat, error) {
	switch x := v.(type) {
	case int:
		return big.NewRat(int64(x), 1), nil
	case int64:
		return big.NewRat(x, 1), nil
	case uint64:
		return new(big.Rat).SetInt(new(big.Int).SetUint64(x)), nil
	case float64:
		return new(big.Rat).SetFloat64(x), nil
	case *big.Float:
		r, _ := x.Rat(nil)
		return r, nil
	case *big.Int:
		return new(big.Rat).SetInt(x), nil
	case *bignum.Complex:
		if x[1].Sign() != 0 {
			return nil, fmt.Errorf("complex scalar unsupported")
		}
		r, _ := x[0].Rat(nil)
		return r, nil
	default:
		return nil, fmt.Errorf("unsupported scalar %T", v)
	}
}
func backendScalar(v rlwe.Operand, prec uint) (*big.Float, error) {
	c := bignum.ToComplex(v, prec)
	if c[1].Sign() != 0 {
		return nil, fmt.Errorf("non-real scalar")
	}
	return c[0], nil
}
func roundedScalar(c *big.Float, f rlwe.Scale) *big.Int {
	r := new(big.Float).Mul(c, &f.Value)
	if c.Sign() > 0 {
		r.Add(r, big.NewFloat(.5))
	} else if c.Sign() < 0 {
		r.Sub(r, big.NewFloat(.5))
	}
	n, _ := r.Int(nil)
	return n
}
func (e *graphEvaluator) apply(op string, a *rlwe.Ciphertext, b rlwe.Operand, o *rlwe.Ciphertext, relin bool) error {
	if e.delegate != nil {
		return e.observe(op, a, b, o, relin)
	}
	ai, err := e.id(a)
	if err != nil {
		return err
	}
	Da := scaleRat(a.Scale)
	n := GraphNode{Op: op, Inputs: []int{ai}, Relin: relin}
	degree, level := a.Degree(), a.Level()
	D := a.Scale
	ct, _ := b.(*rlwe.Ciphertext)
	if ct != nil {
		i, x := e.id(ct)
		if x != nil {
			return x
		}
		n.Inputs = append(n.Inputs, i)
		level = min(level, ct.Level())
	}
	level = min(level, o.Level())
	var oldAcc *big.Rat
	if op == "mul_then_add" {
		i, x := e.id(o)
		if x != nil {
			return x
		}
		n.Inputs = append(n.Inputs, i)
		oldAcc = scaleRat(o.Scale)
	}
	switch op {
	case "relinearize":
		degree = 1
		n.Factor = "1"
		n.Relin = true
	case "rescale":
		cnt := e.params.LevelsConsumedPerRescaling()
		if a.Level() < cnt {
			return fmt.Errorf("insufficient rescale level")
		}
		level = a.Level() - cnt
		dd := ri(1)
		for j := 0; j < cnt; j++ {
			q := e.params.Q()[a.Level()-j]
			n.Primes = append(n.Primes, fmt.Sprint(q))
			dd = mul(dd, new(big.Rat).SetInt(new(big.Int).SetUint64(q)))
			D = D.Div(rlwe.NewScale(q))
		}
		n.Factor = div(Da, mul(dd, scaleRat(D))).RatString()
	case "add", "sub":
		sign := ri(1)
		if op == "sub" {
			sign = ri(-1)
		}
		if ct != nil {
			Db := scaleRat(ct.Scale)
			if ct.Scale.Cmp(D) > 0 {
				D = ct.Scale
			}
			ia, ib := big.NewInt(1), big.NewInt(1)
			if a.Scale.Cmp(ct.Scale) < 0 {
				v := ct.Scale.Div(a.Scale)
				ia, _ = v.Value.Int(nil)
			} else if a.Scale.Cmp(ct.Scale) > 0 {
				v := a.Scale.Div(ct.Scale)
				ib, _ = v.Value.Int(nil)
			}
			if a.Scale.Cmp(ct.Scale) != 0 {
				n.ImplicitScalarMultiplications = 1
			}
			fa, _ := backendScalar(ia, e.params.EncodingPrecision())
			fb, _ := backendScalar(ib, e.params.EncodingPrecision())
			ia = roundedScalar(fa, rlwe.NewScale(1))
			ib = roundedScalar(fb, rlwe.NewScale(1))
			n.Factor = div(mul(Da, new(big.Rat).SetInt(ia)), scaleRat(D)).RatString()
			n.AccFactor = div(mul(sign, mul(Db, new(big.Rat).SetInt(ib))), scaleRat(D)).RatString()
			degree = max(degree, ct.Degree())
		} else {
			v, x := scalarOriginal(b)
			if x != nil {
				return x
			}
			f, x := backendScalar(b, e.params.EncodingPrecision())
			if x != nil {
				return x
			}
			n.Scalar = mul(sign, v).RatString()
			n.Constant = div(mul(sign, new(big.Rat).SetInt(roundedScalar(f, a.Scale))), Da).RatString()
			n.Factor = "1"
		}
	case "mul", "mul_then_add":
		if ct != nil {
			if op == "mul_then_add" {
				return fmt.Errorf("ciphertext fused accumulation outside graph contract")
			}
			D = a.Scale.Mul(ct.Scale)
			degree = a.Degree() + ct.Degree()
			if relin {
				degree = 1
			}
			n.Factor = div(mul(Da, scaleRat(ct.Scale)), scaleRat(D)).RatString()
		} else {
			v, x := scalarOriginal(b)
			if x != nil {
				return x
			}
			f, x := backendScalar(b, e.params.EncodingPrecision())
			if x != nil {
				return x
			}
			n.Scalar = v.RatString()
			F := rlwe.NewScale(1)
			am := ri(1)
			if op == "mul_then_add" {
				if a.Scale.Cmp(o.Scale) > 0 {
					return fmt.Errorf("fused accumulator has smaller scale")
				}
				D = o.Scale
				if a.Scale.Cmp(o.Scale) < 0 {
					F = o.Scale.Div(a.Scale)
				} else if !f.IsInt() {
					F = rlwe.NewScale(e.params.Q()[level])
					for j := 1; j < e.params.LevelsConsumedPerRescaling(); j++ {
						F = F.Mul(rlwe.NewScale(e.params.Q()[level-j]))
					}
					v, _ := F.Value.Int(nil)
					fv, _ := backendScalar(v, e.params.EncodingPrecision())
					am = new(big.Rat).SetInt(roundedScalar(fv, rlwe.NewScale(1)))
					n.ImplicitScalarMultiplications = 1
					D = o.Scale.Mul(F)
				}
				n.AccFactor = div(mul(oldAcc, am), scaleRat(D)).RatString()
			} else {
				if !f.IsInt() {
					F = rlwe.NewScale(e.params.Q()[level])
					for j := 1; j < e.params.LevelsConsumedPerRescaling(); j++ {
						F = F.Mul(rlwe.NewScale(e.params.Q()[level-j]))
					}
				}
				D = a.Scale.Mul(F)
			}
			n.Factor = div(mul(Da, new(big.Rat).SetInt(roundedScalar(f, F))), scaleRat(D)).RatString()
		}
	default:
		return fmt.Errorf("unknown operation %s", op)
	}
	if e.delegate != nil {
		switch op {
		case "add":
			err = e.delegate.Add(a, b, o)
		case "sub":
			err = e.delegate.Sub(a, b, o)
		case "mul":
			if relin {
				err = e.delegate.MulRelin(a, b, o)
			} else {
				err = e.delegate.Mul(a, b, o)
			}
		case "mul_then_add":
			err = e.delegate.MulThenAdd(a, b, o)
		case "relinearize":
			err = e.delegate.Relinearize(a, o)
		case "rescale":
			err = e.delegate.Rescale(a, o)
		}
		if err != nil {
			return err
		}
		want := GraphState{level, degree, scaleRat(D).RatString()}
		if graphState(o) != want {
			return fmt.Errorf("backend metadata mismatch %s: got %+v want %+v", op, graphState(o), want)
		}
	} else {
		md := a.MetaData.CopyNew()
		o.Resize(degree, level)
		o.MetaData = md
		o.Scale = D
	}
	e.append(o, n)
	return nil
}
func (e *graphEvaluator) fresh(a *rlwe.Ciphertext, b rlwe.Operand, op string, r bool) (*rlwe.Ciphertext, error) {
	d, l := a.Degree(), a.Level()
	if c, ok := b.(*rlwe.Ciphertext); ok {
		l = min(l, c.Level())
		if op == "mul" {
			d += c.Degree()
		} else {
			d = max(d, c.Degree())
		}
	}
	if r {
		d = 1
	}
	o := ckks.NewCiphertext(e.params, d, l)
	return o, e.apply(op, a, b, o, r)
}
func (e *graphEvaluator) Add(a *rlwe.Ciphertext, b rlwe.Operand, o *rlwe.Ciphertext) error {
	return e.apply("add", a, b, o, false)
}
func (e *graphEvaluator) AddNew(a *rlwe.Ciphertext, b rlwe.Operand) (*rlwe.Ciphertext, error) {
	return e.fresh(a, b, "add", false)
}
func (e *graphEvaluator) Sub(a *rlwe.Ciphertext, b rlwe.Operand, o *rlwe.Ciphertext) error {
	return e.apply("sub", a, b, o, false)
}
func (e *graphEvaluator) SubNew(a *rlwe.Ciphertext, b rlwe.Operand) (*rlwe.Ciphertext, error) {
	return e.fresh(a, b, "sub", false)
}
func (e *graphEvaluator) Mul(a *rlwe.Ciphertext, b rlwe.Operand, o *rlwe.Ciphertext) error {
	return e.apply("mul", a, b, o, false)
}
func (e *graphEvaluator) MulNew(a *rlwe.Ciphertext, b rlwe.Operand) (*rlwe.Ciphertext, error) {
	return e.fresh(a, b, "mul", false)
}
func (e *graphEvaluator) MulRelin(a *rlwe.Ciphertext, b rlwe.Operand, o *rlwe.Ciphertext) error {
	return e.apply("mul", a, b, o, true)
}
func (e *graphEvaluator) MulRelinNew(a *rlwe.Ciphertext, b rlwe.Operand) (*rlwe.Ciphertext, error) {
	return e.fresh(a, b, "mul", true)
}
func (e *graphEvaluator) MulThenAdd(a *rlwe.Ciphertext, b rlwe.Operand, o *rlwe.Ciphertext) error {
	return e.apply("mul_then_add", a, b, o, false)
}
func (e *graphEvaluator) Relinearize(a, o *rlwe.Ciphertext) error {
	return e.apply("relinearize", a, nil, o, true)
}
func (e *graphEvaluator) Rescale(a, o *rlwe.Ciphertext) error {
	return e.apply("rescale", a, nil, o, false)
}
func runPolynomialGraph(p ckks.Parameters, ct *rlwe.Ciphertext, poly bignum.Polynomial, target rlwe.Scale, e *graphEvaluator, prepared ...*cp.Evaluator) (*rlwe.Ciphertext, error) {
	e.root(ct)
	t, err := e.MulNew(ct, 16)
	if err != nil {
		return nil, err
	}
	if err = e.Add(t, -13, t); err != nil {
		return nil, err
	}
	pb := common.NewPowerBasis(t, bignum.Chebyshev)
	id, err := e.id(t)
	if err != nil {
		return nil, err
	}
	e.bind(pb.Value[1], id)
	var pe *cp.Evaluator
	if len(prepared) > 0 {
		pe = prepared[0]
	} else {
		pe = cp.NewEvaluator(p, e.Evaluator)
	}
	pe.Evaluator.Evaluator = e
	out, err := pe.EvaluateFromPowerBasis(pb, poly, target)
	if err != nil {
		return nil, err
	}
	e.graph.Output, err = e.id(out)
	return out, err
}
func planPolynomialGraph(p ckks.Parameters, b BranchSpec) (PolynomialGraph, error) {
	ct := ckks.NewCiphertext(p, 1, p.MaxLevel())
	ct.Scale = scale(pow2(b.ScaleBits))
	coeff, _ := power16Chebyshev()
	v := make([]*big.Float, 7)
	for i := range v {
		v[i] = bf(coeff[i], 512)
	}
	e := newGraphEvaluator(p, ckks.NewEvaluator(p, nil), nil)
	_, err := runPolynomialGraph(p, ct, bignum.NewPolynomial(bignum.Chebyshev, v, [2]float64{-1, 1}), ct.Scale, e)
	return e.graph, err
}

// Runtime path only records dependencies, scalars and public metadata. Exact
// certificate algebra is done during preparation; graph audit is OUTSIDE timing.
func (e *graphEvaluator) observe(op string, a *rlwe.Ciphertext, b rlwe.Operand, o *rlwe.Ciphertext, relin bool) error {
	id, err := e.id(a)
	if err != nil {
		return err
	}
	n := GraphNode{Op: op, Inputs: []int{id}, Relin: relin}
	if ct, ok := b.(*rlwe.Ciphertext); ok {
		if (op == "add" || op == "sub") && a.Scale.Cmp(ct.Scale) != 0 {
			n.ImplicitScalarMultiplications = 1
		}
		j, x := e.id(ct)
		if x != nil {
			return x
		}
		n.Inputs = append(n.Inputs, j)
	} else if b != nil {
		v, x := scalarOriginal(b)
		if x != nil {
			return x
		}
		if op == "sub" {
			v = neg(v)
		}
		n.Scalar = v.RatString()
	}
	if op == "mul_then_add" {
		if a.Scale.Cmp(o.Scale) == 0 {
			f, x := backendScalar(b, e.params.EncodingPrecision())
			if x != nil {
				return x
			}
			if !f.IsInt() {
				n.ImplicitScalarMultiplications = 1
			}
		}
		j, x := e.id(o)
		if x != nil {
			return x
		}
		n.Inputs = append(n.Inputs, j)
	}
	if op == "rescale" {
		for j := 0; j < e.params.LevelsConsumedPerRescaling(); j++ {
			n.Primes = append(n.Primes, fmt.Sprint(e.params.Q()[a.Level()-j]))
		}
	}
	switch op {
	case "add":
		err = e.delegate.Add(a, b, o)
	case "sub":
		err = e.delegate.Sub(a, b, o)
	case "mul":
		if relin {
			err = e.delegate.MulRelin(a, b, o)
		} else {
			err = e.delegate.Mul(a, b, o)
		}
	case "mul_then_add":
		err = e.delegate.MulThenAdd(a, b, o)
	case "relinearize":
		err = e.delegate.Relinearize(a, o)
	case "rescale":
		err = e.delegate.Rescale(a, o)
	default:
		return fmt.Errorf("unknown runtime graph operation")
	}
	if err != nil {
		return err
	}
	e.append(o, n)
	return nil
}
func auditPolynomialGraph(actual *PolynomialGraph, expected PolynomialGraph) error {
	if actual == nil || actual.Output != expected.Output || len(actual.Nodes) != len(expected.Nodes) {
		return fmt.Errorf("actual polynomial graph shape differs")
	}
	for i := range actual.Nodes {
		a, b := actual.Nodes[i], expected.Nodes[i]
		a.Factor = ""
		a.AccFactor = ""
		a.Constant = ""
		b.Factor = ""
		b.AccFactor = ""
		b.Constant = ""
		if !reflect.DeepEqual(a, b) {
			return fmt.Errorf("actual polynomial graph node %d differs from certificate", i)
		}
	}
	// Attach only the already audited deterministic scalar/metadata model.
	for i := range actual.Nodes {
		actual.Nodes[i].Factor = expected.Nodes[i].Factor
		actual.Nodes[i].AccFactor = expected.Nodes[i].AccFactor
		actual.Nodes[i].Constant = expected.Nodes[i].Constant
	}
	return nil
}
