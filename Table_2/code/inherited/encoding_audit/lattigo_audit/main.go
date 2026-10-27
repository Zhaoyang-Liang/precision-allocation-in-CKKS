// Public, deterministic arithmetic/encoding checks only. No encryption or keys.
package main

import (
 "encoding/json"
 "flag"
 "fmt"
 "math/big"
 "os"
 "github.com/tuneinsight/lattigo/v6/core/rlwe"
 "github.com/tuneinsight/lattigo/v6/schemes/ckks"
 "github.com/tuneinsight/lattigo/v6/utils/bignum"
)

type Spec struct { Name string `json:"name"`; A string `json:"a"`; B string `json:"b"`; Scale string `json:"scale"` }
func integer(s string)*big.Int{v,ok:=new(big.Int).SetString(s,10);if !ok{panic(s)};return v}
func rational(s string)*big.Rat{v,ok:=new(big.Rat).SetString(s);if !ok{panic(s)};return v}
func fl(x *big.Rat,p uint)*big.Float{return new(big.Float).SetPrec(p).SetRat(x)}
func rat(x *big.Float)string{r,_:=x.Rat(nil);return r.RatString()}
func main(){
 input:=flag.String("specs","","public multiplier JSON");out:=flag.String("out","","new output JSON");flag.Parse()
 data,e:=os.ReadFile(*input);if e!=nil{panic(e)};var specs []Spec;if e=json.Unmarshal(data,&specs);e!=nil{panic(e)}
 const precision=uint(512)
 params,e:=ckks.NewParametersFromLiteral(ckks.ParametersLiteral{LogN:15,Q:[]uint64{144115188075593729,144115188075134977,1152921504606584833},LogDefaultScale:74});if e!=nil{panic(e)}
 encoder:=ckks.NewEncoder(params,precision)
 root:=new(big.Float).SetPrec(precision).Sqrt(new(big.Float).SetPrec(precision).SetInt64(2))
 rows:=[]map[string]interface{}{}
 for _,s:=range specs{
  a,b:=integer(s.A),integer(s.B);norm:=new(big.Int).Sub(new(big.Int).Mul(a,a),new(big.Int).Lsh(new(big.Int).Mul(b,b),1));if norm.Sign()==0{panic("zero norm")}
  af:=new(big.Float).SetPrec(precision).SetInt(a);bf:=new(big.Float).SetPrec(precision).SetInt(b)
  term:=new(big.Float).SetPrec(precision).Mul(root,bf)
  weights:=[2]*big.Float{new(big.Float).SetPrec(precision).Add(af,term),new(big.Float).SetPrec(precision).Sub(af,term)}
  for _,complexInput:=range []bool{false,true}{
   xr:=rational("13/16");xi:=rational("0");if complexInput{xr=rational("3/4");xi=rational("1/8")}
   values:=make([]*bignum.Complex,params.MaxSlots())
   for i:=range values{values[i]=&bignum.Complex{new(big.Float).SetPrec(precision).Quo(fl(xr,precision),weights[i%2]),new(big.Float).SetPrec(precision).Quo(fl(xi,precision),weights[i%2])}}
   pt:=ckks.NewPlaintext(params,params.MaxLevel());pt.Scale=rlwe.NewScale(fl(rational(s.Scale),128))
   if e=encoder.Encode(values,pt);e!=nil{panic(e)}
   poly:=pt.Value.CopyNew();params.RingQ().INTT(*poly,*poly);if pt.IsMontgomery{params.RingQ().IMForm(*poly,*poly)}
   coeff:=make([]*big.Int,params.N());for i:=range coeff{coeff[i]=new(big.Int)};params.RingQ().PolyToBigintCentered(*poly,1,coeff)
   expected:=make([]*big.Rat,params.N());for i:=range expected{expected[i]=new(big.Rat)}
   // (xr+i*xi)*(a-b*h)/Norm(p), multiplied by the actual metadata scale.
   for _,piece:=range []struct{index int;c *big.Int}{{0,a},{params.N()/4,new(big.Int).Neg(b)},{3*params.N()/4,b}}{
    base:=new(big.Rat).Mul(rational(s.Scale),new(big.Rat).SetFrac(piece.c,norm))
    expected[piece.index].Add(expected[piece.index],new(big.Rat).Mul(base,xr))
    k:=piece.index+params.N()/2;v:=new(big.Rat).Mul(base,xi);if k>=params.N(){k-=params.N();v.Neg(v)};expected[k].Add(expected[k],v)
   }
   max:=new(big.Rat);for i:=range coeff{v:=new(big.Rat).Sub(new(big.Rat).SetInt(coeff[i]),expected[i]);v.Abs(v);if v.Cmp(max)>0{max.Set(v)}}
   if max.Cmp(rational("1"))>0{panic(fmt.Sprintf("public encoding identity failed: %s %s",s.Name,max))}
   rows=append(rows,map[string]interface{}{"name":s.Name,"complex_input":complexInput,"precision":fmt.Sprint(precision),"N":fmt.Sprint(params.N()),"scale_actual":rat(&pt.Scale.Value),"float_weights":[]string{rat(weights[0]),rat(weights[1])},"max_coefficient_error":max.RatString(),"all_coefficients_checked":fmt.Sprint(params.N())})
  }
 }
 result:=map[string]interface{}{"operation":"public plaintext encoding only; no keys or ciphertext evaluation","pi":rat(bignum.Pi(precision)),"sqrt2":rat(root),"records":rows}
 encoded,e:=json.MarshalIndent(result,"","  ");if e!=nil{panic(e)}
 f,e:=os.OpenFile(*out,os.O_WRONLY|os.O_CREATE|os.O_EXCL,0644);if e!=nil{panic(e)};defer f.Close();if _,e=f.Write(append(encoded,'\n'));e!=nil{panic(e)};if e=f.Sync();e!=nil{panic(e)}
 fmt.Printf("%d full-ring public encoding checks passed\n",len(rows))
}
