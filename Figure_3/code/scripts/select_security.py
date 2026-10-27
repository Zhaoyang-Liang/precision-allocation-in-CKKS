#!/usr/bin/env python3
"""Select from registered finite public pools with actual lattice estimates.

Run under Sage. The two priorities are registered before any timing is read.
No monotonic interpolation of security and no global-optimum claim are used.
Every preceding rejected/unknown candidate remains in the decision record.
"""
import argparse
import csv
import hashlib
import json
import math
from pathlib import Path
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT/'code/security'))
from estimate_cases import reusable_estimates
from estimate_ranked_candidates import rejection_witness

NUMERIC = ('messages', 'precision_bits', 'depth', 'N', 'classes', 'theta',
           'Q_bits', 'Q_count', 'P_count', 'P_bits', 'QP_bits', 'scale_bits',
           'offset', 'output_slack', 'P_width', 'batches', 'capacity',
           'square_Q_words', 'ks_transform_word_proxy', 'public_correction_words',
           'relin_bytes', 'public_key_bytes', 'input_bytes', 'output_bytes')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def put(path, data):
    with Path(path).open('x') as f:
        json.dump(data, f, indent=2)
        f.write('\n')


def read_pool(paths):
    rows = {}
    for path in paths:
        with Path(path).open() as f:
            for r in csv.DictReader(f):
                for key in NUMERIC:
                    r[key] = int(r[key])
                if r['conditional_correctness'] != 'True' or int(r['HE_executions']) != 0:
                    raise ValueError('Only certified public candidates are selectable')
                q, p = list(map(int, r['Q'].split('|'))), list(map(int, r['P'].split('|')))
                if (math.prod(q)-1).bit_length() != r['Q_bits'] or (math.prod(q+p)-1).bit_length() != r['QP_bits']:
                    raise ValueError('CSV modulus mismatch')
                if len(q) != r['Q_count'] or len(p) != r['P_count'] or len(set(q+p)) != len(q+p):
                    raise ValueError('CSV prime count/uniqueness mismatch')
                cid = r['candidate_id']
                if cid in rows:
                    # Provenance paths can differ when a candidate is re-queried.
                    fields = ('N', 'classes', 'theta', 'Q', 'P', 'scale_bits', 'rescale_counts', 'task_id')
                    if any(rows[cid][k] != r[k] for k in fields):
                        raise ValueError('Candidate hash collision or inconsistent repeated row')
                else:
                    rows[cid] = r
    return list(rows.values())


def workload(row, messages):
    batches = (messages+row['capacity']-1)//row['capacity']
    work = {}
    for key in ('square_Q_words', 'ks_transform_word_proxy', 'public_correction_words', 'input_bytes', 'output_bytes'):
        if row[key] % row['batches']:
            raise ValueError('Nonintegral per-batch resource')
        work[key] = row[key]//row['batches']*batches
    work['batches'] = batches
    work['online_word_proxy'] = sum(work[k] for k in ('square_Q_words', 'ks_transform_word_proxy', 'public_correction_words'))
    work['memory_guard_bytes'] = 4*(work['input_bytes']+work['output_bytes']+row['relin_bytes']+row['public_key_bytes'])
    work['secret_count'] = batches+1
    work['error_count'] = 4*batches+4+4*((row['Q_count']+row['P_count']-1)//row['P_count'])
    return work


def order_key(row, messages, priority):
    w = workload(row, messages)
    tie = (row['Q_bits'], row['Q_count'], w['online_word_proxy'], row['QP_bits'], row['theta'], row['candidate_id'])
    if priority == 'min_N_then_Q':
        return (row['N'],)+tie
    if priority == 'online_word_proxy':
        return (w['online_word_proxy'], row['N'])+tie
    raise ValueError(priority)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--csv', action='append', required=True)
    ap.add_argument('--tasks', required=True, help='JSON object with tasks list')
    ap.add_argument('--out', required=True)
    ap.add_argument('--reuse', action='append', default=[])
    ap.add_argument('--estimator', default='/Users/mac/opt/lattice-estimator')
    ap.add_argument('--shard', type=int, default=0)
    ap.add_argument('--shards', type=int, default=1)
    ap.add_argument('--pilot', action='store_true')
    args = ap.parse_args()
    if not 0 <= args.shard < args.shards:
        raise ValueError('Invalid shard')
    out = Path(args.out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    paths = [Path(p).resolve() for p in args.csv]
    rows = read_pool(paths)
    tasks = json.loads(Path(args.tasks).read_text())['tasks']
    tasks = sorted(tasks, key=lambda t: (t['precision_bits'], t['depth'], t['input_family'], t['messages'], t['id']))
    # Keep all M for a mathematical task together, maximizing exact-input reuse.
    keys = sorted({(t['precision_bits'], t['depth'], t['input_family']) for t in tasks})
    keys = set(keys[args.shard::args.shards])
    tasks = [t for t in tasks if (t['precision_bits'], t['depth'], t['input_family']) in keys]
    registration = {'schema': 'pa07-security-selection-registration-v1', 'pilot_only': args.pilot,
        'tasks': tasks, 'priorities': ['min_N_then_Q', 'online_word_proxy'],
        'priority_definitions': {
            'min_N_then_Q': 'N, Q bits, Q limb count, online word proxy, QP bits, theta, candidate id',
            'online_word_proxy': 'sum(square Q words, key-switch transform-word proxy, correction words) over all batches; then N, Q bits, Q limbs, proxy, QP bits, theta, id'},
        'memory_guard_max_bytes': 8*2**30, 'secret_count_max': 256, 'error_count_max': 4096,
        'pool_files': [{'path': str(p), 'sha256': digest(p)} for p in paths],
        'task_file': {'path': str(Path(args.tasks).resolve()), 'sha256': digest(args.tasks)},
        'script_sha256': digest(__file__), 'candidate_count': len(rows),
        'scope': 'First passing member of each declared finite ordering; no minimum runtime or global optimum claim.',
        'HE_executions': 0}
    put(out/'registration.json', registration)
    repo = Path(args.estimator).resolve()
    commit = subprocess.check_output(['git', '-C', str(repo), 'rev-parse', 'HEAD'], text=True).strip()
    dirty = subprocess.check_output(['git', '-C', str(repo), 'diff', '--name-only', 'HEAD'], text=True).splitlines()
    if dirty:
        raise ValueError('Modified estimator source')
    cache, provenance = reusable_estimates(args.reuse, commit, 128)
    rejected = {}
    for name in args.reuse:
        prior_raw = Path(name).read_bytes()
        prior_digest = hashlib.sha256(prior_raw).hexdigest()
        for row in json.loads(prior_raw).get('early_rejections', []):
            if str(math.prod(map(int, row['Q']+row['P']))) != row['qp_exact'] or (int(row['qp_exact'])-1).bit_length() != row['q_est_log2']:
                raise ValueError('Prior rejection input mismatch')
            if rejection_witness(row['attacks']) is None:
                raise ValueError('Prior rejection lacks a real attack witness')
            rejected[(row['N'], row['q_est_log2'])] = {'attacks': row['attacks'], 'origin_file_sha256': prior_digest}
    sys.path.insert(0, str(repo))
    from sage.all import ZZ, oo, log
    from estimator import LWE, ND, RC
    attacks = {'primal_usvp': LWE.primal_usvp, 'primal_bdd': LWE.primal_bdd, 'dual_hybrid': LWE.dual_hybrid}
    wrapper = out/'security.wrapper.py'
    wrapper.write_bytes(Path(__file__).read_bytes())
    result = {'schema': 'ckks-new-security-v1', 'estimator_commit': commit, 'estimator_tracked_dirty': [],
        'wrapper_sha256': digest(wrapper), 'wrapper_source_file': str(wrapper),
        'selection_registration_sha256': digest(out/'registration.json'),
        'model': 'RC.MATZOV', 'secret': 'uniform_ternary', 'error_sigma': '3.2',
        'actual_sampler_abs_bound': '19.2', 'samples': 'infinity', 'target_bits': 128,
        'HE_executions': 0, 'cases': [], 'early_rejections': [], 'estimator_errors': [],
        'reused_result_files': provenance, 'new_attack_calls': 0, 'reused_cases': 0,
        'reported_log_precision': 'Numerical lattice-estimator work factors, not a proof.'}
    completed, unknown, decisions = {}, {}, []
    with (out/'security.cases.jsonl').open('x') as stream, (out/'decisions.jsonl').open('x') as decision_stream:
        def estimate(r):
            exact = (r['N'], r['Q'], r['P'])
            if exact in completed:
                return completed[exact]
            q, p = r['Q'].split('|'), r['P'].split('|')
            case = {'branch': r['candidate_id'], 'N': r['N'], 'Q': q, 'P': p,
                    'qp_exact': str(math.prod(map(int, q+p))), 'q_est_log2': r['QP_bits']}
            key = (r['N'], r['QP_bits'])
            if key not in cache and key not in rejected and key not in unknown:
                params = LWE.Parameters(n=r['N'], q=ZZ(2)**r['QP_bits'], Xs=ND.Ternary,
                         Xe=ND.DiscreteGaussian(3.2), m=oo, tag=f'N{key[0]}_qbits{key[1]}')
                values = {}
                try:
                    for name, attack in attacks.items():
                        start = time.monotonic()
                        answer = attack(params, red_cost_model=RC.MATZOV)
                        bits = str(log(answer['rop'], 2).n())
                        finite = math.isfinite(float(bits))
                        values[name] = {'cost': {str(k): str(v) for k, v in answer.items()},
                            'log2_rop': bits, 'finite_estimate': finite,
                            'target_pass': finite and bool(answer['rop'] >= ZZ(2)**128),
                            'wall_seconds': time.monotonic()-start}
                        result['new_attack_calls'] += 1
                        print(key, name, bits, flush=True)
                        if rejection_witness(values) is not None:
                            rejected[key] = {'attacks': values, 'origin': 'computed_in_this_execution'}
                            break
                    else:
                        cache[key] = {'attacks': values, 'origin': 'computed_in_this_execution'}
                except Exception as exc:
                    unknown[key] = {'attacks': values, 'error': repr(exc)}
                    print('ESTIMATOR ERROR', key, repr(exc), flush=True)
            else:
                result['reused_cases'] += 1
            if key in unknown:
                record = dict(case, **unknown[key], all_three_attacks_pass=False, status='estimator_error')
                result['estimator_errors'].append(record)
                verdict = {'pass': False, 'reason': 'estimator_error', 'security_case': case['branch']}
            else:
                entry = rejected.get(key, cache.get(key))
                record = dict(case, attacks=entry['attacks'], estimate_provenance={k: v for k, v in entry.items() if k != 'attacks'})
                passed = len(record['attacks']) == 3 and all(v['target_pass'] for v in record['attacks'].values())
                record['all_three_attacks_pass'] = passed
                witness = rejection_witness(record['attacks'])
                if witness:
                    record['rejection_witness'] = witness
                result['early_rejections' if key in rejected else 'cases'].append(record)
                verdict = {'pass': passed, 'reason': 'three_finite_attacks_pass' if passed else
                           ('actual_below_target_attack' if witness else 'nonfinite_estimate_not_accepted'),
                           'security_case': case['branch']}
            stream.write(json.dumps(record)+'\n'); stream.flush()
            completed[exact] = verdict
            return verdict

        for task in tasks:
            pool = [r for r in rows if (r['precision_bits'], r['depth'], r['input_family']) ==
                    (task['precision_bits'], task['depth'], task['input_family'])]
            if not pool:
                raise ValueError('Missing public pool for '+task['id'])
            if 'fixed_N' in task:
                pool = [r for r in pool if r['N'] == task['fixed_N']]
            if 'fixed_theta' in task:
                pool = [r for r in pool if r['theta'] == task['fixed_theta']]
            for classes in task.get('class_counts', (1, 2, 4)):
                members = [r for r in pool if r['classes'] == classes]
                for priority in task.get('priorities', registration['priorities']):
                    if priority not in registration['priorities']:
                        raise ValueError('Unregistered curve priority')
                    visited, winner = [], None
                    for r in sorted(members, key=lambda row: order_key(row, task['messages'], priority)):
                        w = workload(r, task['messages'])
                        if w['memory_guard_bytes'] > 8*2**30:
                            verdict = {'pass': False, 'reason': 'implementation_memory_guard'}
                        elif w['secret_count'] > 256 or w['error_count'] > 4096:
                            verdict = {'pass': False, 'reason': 'sampled_family_limit'}
                        else:
                            verdict = estimate(r)
                        visited.append({'candidate_id': r['candidate_id'], **verdict})
                        if verdict['pass']:
                            winner = r
                            break
                    decision = {'task': task, 'classes': classes, 'priority': priority,
                        'selected_source_candidate_id': winner['candidate_id'] if winner else None,
                        'candidate_pool_count': len(members), 'visited_prefix': visited,
                        'workload': workload(winner, task['messages']) if winner else None}
                    decisions.append(decision)
                    decision_stream.write(json.dumps(decision)+'\n'); decision_stream.flush()
                    print('SELECTED', task['id'], classes, priority,
                          (winner['N'], winner['Q_bits'], winner['theta']) if winner else None, len(visited), flush=True)
    result['all_cases_pass'] = not result['early_rejections'] and not result['estimator_errors'] and all(r['all_three_attacks_pass'] for r in result['cases'])
    put(out/'security.json', result)
    put(out/'decisions.json', {'registration_sha256': digest(out/'registration.json'), 'decisions': decisions})
    fields = ['task_id', 'messages', 'precision_bits', 'depth', 'input_family', 'classes', 'priority',
              'selected_source_candidate_id', 'N', 'Q_bits', 'Q_count', 'QP_bits', 'theta', 'batches',
              'online_word_proxy', 'memory_guard_bytes', 'visited_count']
    by_id = {r['candidate_id']: r for r in rows}
    with (out/'decisions.csv').open('x', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields); writer.writeheader()
        for d in decisions:
            r = by_id.get(d['selected_source_candidate_id'], {})
            writer.writerow(dict(task_id=d['task']['id'], **{k: d['task'][k] for k in ('messages','precision_bits','depth','input_family')},
                **{k: d[k] for k in ('classes','priority','selected_source_candidate_id')},
                **{k: r.get(k) for k in ('N','Q_bits','Q_count','QP_bits','theta')},
                **{k: (d['workload'] or {}).get(k) for k in ('batches','online_word_proxy','memory_guard_bytes')},
                visited_count=len(d['visited_prefix'])))
    print('DONE', len(decisions), 'decisions;', result['new_attack_calls'], 'new attack calls', flush=True)


if __name__ == '__main__':
    sys.set_int_max_str_digits(0)
    main()
