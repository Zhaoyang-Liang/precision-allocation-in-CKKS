#!/usr/bin/env python3
"""Measure cold public unit construction separately from online HE work."""
import argparse
import csv
import json
from pathlib import Path
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source-root', default='.')
    ap.add_argument('--selection')
    ap.add_argument('--out')
    ap.add_argument('--child-row', help='Internal fresh-process construction check')
    args = ap.parse_args()
    source = (ROOT/args.source_root).resolve()
    sys.path.insert(0, str(source/'code'))
    from cost_experiment import unit
    if args.child_row:
        row = json.loads(Path(args.child_row).read_text())
        start = time.perf_counter_ns()
        value = unit(row['classes'], row['theta'])
        elapsed = time.perf_counter_ns()-start
        expected = row['branch']['multiplier']
        if value is not None and (value['coefficients'] != expected['coefficients'] or value['inverse_coefficients'] != expected['inverse_coefficients']):
            raise ValueError('Cold construction differs from frozen public multiplier')
        print(json.dumps({'candidate_id': row['id'], 'classes': row['classes'], 'theta': row['theta'],
            'construction_ms': elapsed/1e6 if value is not None else 0,
            'unit_coefficient_bits': row['unit']['coefficient_bits'],
            'inverse_coefficient_bits': row['unit']['inverse_coefficient_bits']}))
        return
    selection = Path(args.selection).resolve()
    out = Path(args.out).resolve(); out.mkdir(exist_ok=False)
    manifest = json.loads(selection.read_text())
    rows = []
    for item in manifest['candidates']:
        summary = json.loads((selection.parent/item['summary']).read_text())
        row = next(r for r in summary['frontier'] if r['id'] == item['candidate_id'])
        row_path = out/(row['id']+'.input.json')
        row_path.write_text(json.dumps(row))
        for repeat in range(1,6):
            result = subprocess.run([sys.executable, str(Path(__file__).resolve()), '--source-root', str(source),
                                     '--child-row', str(row_path)], text=True, capture_output=True)
            if result.returncode:
                (out/(row['id']+f'.r{repeat}.failure.log')).write_text(result.stdout+result.stderr)
                raise RuntimeError('Cold unit construction failed; retained log')
            rows.append(dict(json.loads(result.stdout), repeat=repeat))
    with (out/'unit_preparation.csv').open('x', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    print(len(rows), 'cold construction records; separate from online timing', flush=True)


if __name__ == '__main__':
    main()
