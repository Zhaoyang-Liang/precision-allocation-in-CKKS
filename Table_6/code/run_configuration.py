"""Check a saved configuration; --run explicitly starts a new HE experiment."""
import argparse, os, subprocess
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--binary',required=True,type=Path)
ap.add_argument('--config',required=True,type=Path)
ap.add_argument('--run',action='store_true')
ap.add_argument('--out',type=Path)
args=ap.parse_args()
config=args.config if args.config.is_absolute() else ROOT/args.config
command=[str(args.binary.resolve()),'-mode','run' if args.run else 'check','-config',str(config.resolve())]
if args.run:
    if not args.out:ap.error('--run requires --out')
    if args.out.exists():ap.error('output already exists')
    command+=['-out',str(args.out.resolve())]
subprocess.run(command,check=True,env={**os.environ,'GOMAXPROCS':'1','GOMEMLIMIT':'8GiB'})
