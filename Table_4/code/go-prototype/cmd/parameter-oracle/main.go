package main

import (
	"encoding/json"
	"fmt"
	"github.com/tuneinsight/lattigo/v6/circuits/ckks/mod1"
	"github.com/tuneinsight/lattigo/v6/schemes/ckks"
	lb "lowbootstrap"
	"math"
	"os"
)

type row struct {
	Family                          string
	Degree, ActualDegree, DA, Depth int
	WorstError, Bits, CentralError  float64
	WorstI                          int
	WorstZ                          float64
}

func main() {
	p, e := ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN: 13, LogQ: []int{50, 28, 28, 28, 28, 28, 28, 28, 28, 28}, LogP: []int{53}, LogDefaultScale: 20})
	if e != nil {
		panic(e)
	}
	rows := []row{}
	for _, family := range []mod1.Type{mod1.CosContinuous} {
		for _, da := range []int{0, 1, 2, 3} {
			for _, degree := range []int{31, 63, 127} {

				if family == mod1.CosDiscrete && degree < 33 {
					continue
				}
				lit := mod1.ParametersLiteral{LevelQ: p.MaxLevel(), LogScale: 20, Mod1Type: family, Scaling: math.Exp2(math.Round(math.Log2(float64(p.Q()[0])))) / float64(p.Q()[0]), LogMessageRatio: 4, K: 17, Mod1Degree: degree, DoubleAngle: da}
				plan, e := mod1.NewParametersFromLiteral(p, lit)
				if e != nil {
					panic(e)
				}
				r := row{Family: "discrete", Degree: degree, ActualDegree: plan.Mod1Poly.Degree(), DA: da, Depth: lit.Depth()}
				if family == mod1.CosContinuous {
					r.Family = "continuous"
				}
				for i := -16; i <= 16; i++ {
					for zz := -40; zz <= 40; zz++ {
						z := float64(zz) / 100
						y := 27 * lb.Mod1PlaintextOracle(plan, (float64(i)+z/27)/17)
						err := math.Abs(y - z)
						if math.Abs(float64(i)) <= 5 {
							r.CentralError = math.Max(r.CentralError, err)
						}
						if err > r.WorstError {
							r.WorstError = err
							r.WorstI = i
							r.WorstZ = z
						}
					}
				}
				r.Bits = -math.Log2(r.WorstError)
				rows = append(rows, r)
				fmt.Fprintf(os.Stderr, "%s deg%d actual%d DA%d depth%d worst %.8g bits %.4f central %.8g I%d z%.2f\n", r.Family, r.Degree, r.ActualDegree, r.DA, r.Depth, r.WorstError, r.Bits, r.CentralError, r.WorstI, r.WorstZ)
			}
		}
	}
	b, _ := json.MarshalIndent(rows, "", "  ")
	fmt.Println(string(b))
}
