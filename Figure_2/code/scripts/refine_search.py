#!/usr/bin/env python3
"""Registered local refinement of public parameters, never a global optimizer.

Visit every theta in the registered windows. For each schedule/P width, bracket
a passing scale with P_count=1, inspect each integer in the final bracket, and
check all P counts at the local passing scale and its two neighbours. Every
query is retained. No monotonicity or optimality claim is made for unvisited
scales, transfers, or parameter families. No timing data informs the search.
"""
import argparse
from collections import Counter
import csv
import gzip
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--source-root', default='.')
    ap.add_argument('--task-id', required=True)
    ap.add_argument('--N', type=int, required=True)
    ap.add_argument('--coarse-csv', action='append', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('--classes', type=int, nargs='+', default=[1, 2, 4])
    ap.add_argument('--P-widths', type=int, nargs='+', default=[24, 32, 40, 48, 56, 60])
    ap.add_argument('--shapes', nargs='+', default=['flat', 'alternating', 'deferred_terminal'])
    ap.add_argument('--slacks', type=int, nargs='+', default=[2, 6])
    ap.add_argument('--theta', type=int, nargs='+', help='Explicit registered window, mainly for validation/expansion')
    args = ap.parse_args()
    source = (ROOT/args.source_root).resolve()
    sys.path.insert(0, str(source/'code'))
    from cost_experiment import make_candidate, task, frontier, source_hashes, config_for

    rows, inputs = [], []
    for filename in args.coarse_csv:
        path = (ROOT/filename).resolve()
        raw = path.read_bytes()
        inputs.append({'path': str(path.relative_to(ROOT)), 'sha256': hashlib.sha256(raw).hexdigest()})
        with path.open() as f:
            rows.extend(r for r in csv.DictReader(f) if r['task_id'] == args.task_id)
    if not rows:
        raise ValueError('Task missing from registered public source CSVs')
    first = rows[0]
    t = task(first['scene'], int(first['messages']), int(first['precision_bits']),
             int(first['depth']), first['input_family'])
    windows = {}
    for r in args.classes:
        if r == 1:
            windows[r] = [0]
        elif args.theta is not None:
            windows[r] = sorted(set(args.theta))
        else:
            pool = [x for x in rows if int(x['classes']) == r and int(x['N']) == args.N]
            if not pool:
                # No prior certification is not infeasibility: still search.
                windows[r] = list(range(0, 129))
                continue
            priorities = [lambda x: (int(x['Q_bits']), int(x['QP_bits']), int(x['theta'])),
                          lambda x: (int(x['square_Q_words'])+int(x['ks_transform_word_proxy'])+
                                     int(x['public_correction_words']), int(x['QP_bits']), int(x['theta'])),
                          lambda x: (int(x['relin_bytes']), int(x['Q_bits']), int(x['theta']))]
            centers = {int(min(pool, key=f)['theta']) for f in priorities}
            window = {0}
            for center in centers:
                high = center+(30 if center >= 128 else 10)
                window.update(range(max(0, center-10), high+1))
            windows[r] = sorted(window)
    out = (ROOT/args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    registration = {'stage': 'refinement-v2', 'task': t, 'N': args.N,
                    'theta_windows': windows, 'source_csvs': inputs,
                    'source_sha256': source_hashes(), 'P_widths': args.P_widths,
                    'P_counts': list(range(1, 11)), 'shapes': args.shapes, 'slacks': args.slacks,
                    'scale_floor': 24, 'scale_ceiling': 512, 'Q_limbs_max': 64,
                    'scale_search': 'P1 step-eight bracket; every integer in final bracket; all P counts at best-1,best,best+1',
                    'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                    'no_unvisited_parameter_optimality_claim': True, 'HE_executions': 0}
    with (out/'registration.json').open('x') as f:
        json.dump(registration, f, indent=2)
    memo, cells, failures = {}, {}, Counter()
    counters = {'candidate_count': 0, 'conditional_pass_count': 0}
    started = time.monotonic()
    growth = (2**t['depth']-1) if t['input_family'] == 'grow' else 0
    with gzip.open(out/'all_candidates.jsonl.gz', 'xt', compresslevel=3) as stream:
        def evaluate(r, theta, base, shape, slack, pc, pw):
            identity = (r, theta, base, shape, slack, pc, pw)
            if identity in memo:
                return memo[identity]
            offset = base-(t['precision_bits']-(r-1)*theta+growth+t['depth'])
            recipe = dict(classes=r, theta=theta, N=args.N, base=base, offset=offset,
                          shape=shape, slack=slack, P_count=pc, P_width=pw)
            try:
                row = make_candidate(t, r, theta, args.N, offset, shape, slack, pc, pw, max_q_limbs=64)
            except (ValueError, ArithmeticError) as exc:
                row = {'recipe': recipe, 'conditional_correctness': False,
                       'reasons': ['public_generation:'+str(exc)], 'HE_executions': 0}
            counters['candidate_count'] += 1
            failures.update(row['reasons'])
            stream.write(json.dumps(row, separators=(',', ':'))+'\n')
            passed = row['conditional_correctness']
            if passed:
                counters['conditional_pass_count'] += 1
                cell = (args.N, r, theta)
                cells[cell] = frontier(cells.get(cell, [])+[row])
            memo[identity] = passed
            if counters['candidate_count'] % 1000 == 0:
                stream.flush()
                print(t['id'], args.N, counters, 'seconds', time.monotonic()-started, flush=True)
            return passed

        for r in args.classes:
            for theta in windows[r]:
                for shape in args.shapes:
                    lower = 32 if shape == 'alternating' else 24
                    for slack in args.slacks:
                        for pw in args.P_widths:
                            seed = max(lower, min(512, t['precision_bits']-(r-1)*theta+growth+t['depth']+24))
                            high = seed
                            while not evaluate(r, theta, high, shape, slack, 1, pw):
                                if high == 512:
                                    break
                                high = min(512, high+8)
                            else:
                                low = high
                                while low > lower:
                                    trial = max(lower, low-8)
                                    if not evaluate(r, theta, trial, shape, slack, 1, pw):
                                        low = trial
                                        break
                                    high = low = trial
                                passing = [high]
                                for base in range(low, high):
                                    if evaluate(r, theta, base, shape, slack, 1, pw):
                                        passing.append(base)
                                center = min(passing)
                                for base in range(max(lower, center-1), min(512, center+1)+1):
                                    for pc in range(1, 11):
                                        evaluate(r, theta, base, shape, slack, pc, pw)
    fronts = [row for cell in cells.values() for row in cell]
    best = []
    for r in args.classes:
        pool = [x for x in fronts if x['classes'] == r]
        if pool:
            minimum = min(x['Q_bits_ceiling'] for x in pool)
            winners = sorted({x['theta'] for x in pool if x['Q_bits_ceiling'] == minimum})
            nonzero = [x for x in windows[r] if x > 0]
            edges = [x for x in winners if x > 0 and
                     (x-1 not in windows[r] or x+1 not in windows[r])]
            best.append({'classes': r, 'minimum_tested_Q_bits': minimum, 'winning_thetas': winners,
                         'theta_window_edge_winners': edges,
                         'upper_theta_boundary_winner': bool(nonzero and max(nonzero) in winners)})
    result = {'schema': 'pa-cost-public-search-v1', 'task': t, 'pilot_only': False,
              **counters, 'failure_counts': dict(failures), 'frontier': fronts,
              'theta_upper_boundary_winners': [x for x in best if x['upper_theta_boundary_winner']],
              'best_public': best, 'search_domain_only': True, 'security_estimated': False,
              'HE_executions': 0, 'wall_seconds': time.monotonic()-started,
              'scope': 'Minimum over actually queried public candidates; not an exhaustive/global scale optimizer.'}
    with (out/'summary.json').open('x') as f:
        json.dump(result, f, indent=2)
    print(json.dumps({k: v for k, v in result.items() if k != 'frontier'}), flush=True)


if __name__ == '__main__':
    if hasattr(sys, 'set_int_max_str_digits'):
        sys.set_int_max_str_digits(0)
    main()
