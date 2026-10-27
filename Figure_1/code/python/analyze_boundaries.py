"""Describe measured transition brackets without assuming monotonicity."""
import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path

def write_csv(path,rows):
    with path.open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--runs',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    rows=list(csv.DictReader(args.runs.open()));args.output.mkdir(parents=True,exist_ok=True)
    bounds=[];details=[];examples=[]
    for r in (2,4):
      for family in ('grow','shrink'):
        data=[x for x in rows if int(x['classes'])==r and x['input_family']==family]
        g=defaultdict(list)
        for x in data:g[int(x['theta'])].append(x)
        for depth in range(8):
            outcomes={t:[int(x['last_recoverable_depth'])>=depth for x in v] for t,v in g.items()}
            all_pass=[t for t,v in outcomes.items() if all(v)]
            any_pass=[t for t,v in outcomes.items() if any(v)]
            any_fail=[t for t,v in outcomes.items() if not all(v)]
            all_fail=[t for t,v in outcomes.items() if not any(v)]
            mixed=sorted(t for t,v in outcomes.items() if any(v) and not all(v))
            reversals=[]
            for rep in sorted({int(x['replicate']) for x in data}):
                series=sorted((int(x['theta']),int(x['last_recoverable_depth'])>=depth) for x in data if int(x['replicate'])==rep)
                for (ta,va),(tb,vb) in zip(series,series[1:]):
                    if not va and vb:reversals.append({'replicate':rep,'failed_theta':ta,'later_success_theta':tb})
            b=dict(classes=r,input_family=family,depth=depth,
                largest_tested_theta_all_repeats_pass=max(all_pass) if all_pass else '',
                largest_tested_theta_any_repeat_pass=max(any_pass) if any_pass else '',
                smallest_tested_theta_any_repeat_fails=min(any_fail) if any_fail else '',
                smallest_tested_theta_all_repeats_fail=min(all_fail) if all_fail else '',
                mixed_theta=';'.join(map(str,mixed)),observed_nonmonotone_transitions=len(reversals))
            bounds.append(b);details.append(dict(**b,reversals=reversals,counts={str(t):{'passed':sum(v),'trials':len(v)} for t,v in sorted(outcomes.items())}))
        for theta in (0,64,70,80,90,100,128,200,350,360,700,750):
            if theta not in g:continue
            vals=g[theta];ks=[int(x['last_recoverable_depth']) for x in vals]
            precision=[float(x['last_valid_precision_bits']) for x in vals if x['last_valid_precision_bits']!='']
            examples.append(dict(classes=r,input_family=family,theta=theta,nominal_useful_gain=(r-1)*theta,
                nominal_useful_budget=64+(r-1)*theta,nominal_dummy_budget=64-theta,repeats=len(vals),
                last_recoverable_depth_min=min(ks),last_recoverable_depth_max=max(ks),
                last_valid_precision_min=min(precision) if precision else '',last_valid_precision_max=max(precision) if precision else ''))
    write_csv(args.output/'boundaries.csv',bounds);write_csv(args.output/'examples.csv',examples)
    (args.output/'boundary_details.json').write_text(json.dumps({'scope':'Empirical outcomes on the saved grid and repeated synthetic key families. Gaps between measured theta values are not certified, and unit choices are discrete. Nonmonotonic transitions are listed rather than suppressed. Additional repeats exist at selected boundary points only.','boundaries':details},indent=2)+'\n')
    print(json.dumps({'boundary_rows':len(bounds),'example_rows':len(examples),'nonmonotone_transitions':sum(x['observed_nonmonotone_transitions'] for x in bounds)}))

if __name__=='__main__':main()
