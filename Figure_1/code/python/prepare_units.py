"""Construct exact public units; this script does not execute HE."""
import argparse
import json
import sys
from pathlib import Path
from multipliers import design_profile

if hasattr(sys, 'set_int_max_str_digits'):
    sys.set_int_max_str_digits(0)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--output',type=Path,required=True)
    ap.add_argument('--theta',type=int,nargs='+',required=True)
    ap.add_argument('--base-bits',type=int,default=64)
    ap.add_argument('--precision',type=int,default=8192)
    args=ap.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    for r in (2,4):
        for theta in args.theta:
            path=args.output/f'r{r}_theta{theta:04d}.json'
            if path.exists():
                old=json.loads(path.read_text())
                if old['requested_theta']!=theta or old['mean_target_bits']!=str(args.base_bits) or old['interval_precision_bits']!=args.precision:
                    raise ValueError('existing unit configuration differs')
                continue
            data=design_profile([args.base_bits+(r-1)*theta]+[args.base_bits-theta]*(r-1),precision=args.precision)
            data['requested_theta']=theta
            data['nominal_bits_are_not_accuracy_acceptance_targets']=True
            with path.open('x') as f:json.dump(data,f,ensure_ascii=False,indent=2);f.write('\n')
            print(f'classes={r} theta={theta} coefficient_bits={data["coefficient_bits"]}',flush=True)

if __name__=='__main__':main()
