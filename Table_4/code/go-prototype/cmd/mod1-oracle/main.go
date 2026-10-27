package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"

	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
)

type point struct {
	I                   int
	Z, Output, AbsError float64
	InsideCarryRange    bool
}
type row struct {
	Family                                                                   string
	RequestedDegree, ActualDegree, PolynomialDepth, DoubleAngle, TotalLevels int
	MaxAbsError, Bits, EdgeI16MaxAbsError                                    float64
	WorstI                                                                   int
	WorstZ                                                                   float64
	Points                                                                   []point
}

func main() {
	output := flag.String("out", "", "JSON output (otherwise stdout)")
	flag.Parse()
	p, err := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 10, LogQ: []int{50, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28}, LogP: []int{53}, LogDefaultScale: 28})
	if err != nil {
		panic(err)
	}
	qd := float64(p.Q()[0]) / math.Exp2(math.Round(math.Log2(float64(p.Q()[0]))))
	rows := []row{}
	for _, family := range []struct {
		Name string
		Type mod1.Type
	}{{"CosDiscrete", mod1.CosDiscrete}, {"CosContinuous", mod1.CosContinuous}} {
		for _, da := range []int{3, 4} {
			for _, degree := range []int{31, 35, 39, 47, 63} {
				plan, err := mod1.NewParametersFromLiteral(p, mod1.ParametersLiteral{LevelQ: p.MaxLevel(), LogScale: 28, Mod1Type: family.Type, Scaling: 1 / qd, LogMessageRatio: 13, K: 16, Mod1Degree: degree, DoubleAngle: da})
				if err != nil {
					panic(err)
				}
				r := row{Family: family.Name, RequestedDegree: degree, ActualDegree: plan.Mod1Poly.Degree(), PolynomialDepth: plan.Mod1Poly.Depth(), DoubleAngle: da, TotalLevels: plan.Mod1Poly.Depth() + da}
				for i := -16; i <= 16; i++ {
					for _, z := range []float64{-.9, -.5, -.25, -.1, 0, .1, .25, .5, .9} {
						y := 8192 * lb.Mod1PlaintextOracle(plan, (float64(i)+z/8192)/16)
						e := math.Abs(y - z)
						inside := i > -16 && i < 16
						r.Points = append(r.Points, point{i, z, y, e, inside})
						if inside && e > r.MaxAbsError {
							r.MaxAbsError = e
							r.WorstI = i
							r.WorstZ = z
						}
						if !inside {
							r.EdgeI16MaxAbsError = math.Max(r.EdgeI16MaxAbsError, e)
						}
					}
				}
				r.Bits = -math.Log2(r.MaxAbsError)
				rows = append(rows, r)
				fmt.Fprintf(os.Stderr, "%-13s degree %2d -> %2d DA%d levels%d max %.10g bits %.4f worst I=%d z=%g |I|16error %.10g\n", r.Family, degree, r.ActualDegree, da, r.TotalLevels, r.MaxAbsError, r.Bits, r.WorstI, r.WorstZ, r.EdgeI16MaxAbsError)
			}
		}
	}
	report := struct {
		Contract                                     string
		Q0                                           uint64
		QDiff, Beta, K, ZPoint9SinLinearizationError float64
		Rows                                         []row
	}{
		Contract: "t=(I+z/beta)/K; offset -1/(4K) once; coefficients and DA constants from Lattigo; Scaling=1/QDiff; decoded output beta*y approximates z. |I|<=15 is scored; |I|=16 reported separately, outside approximation's intended strict carry range. Plaintext only; no FHE noise or security claim.", Q0: p.Q()[0], QDiff: qd, Beta: 8192, K: 16, ZPoint9SinLinearizationError: math.Abs(8192*math.Sin(2*math.Pi*.9/8192)/(2*math.Pi) - .9), Rows: rows}
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		panic(err)
	}
	if *output == "" {
		fmt.Println(string(data))
	} else if err = os.WriteFile(*output, append(data, '\n'), 0644); err != nil {
		panic(err)
	}
}
