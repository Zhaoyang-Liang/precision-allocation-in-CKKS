"""Fixed precision experiment: public search, exact inputs, and capacity ledger.

Search results are conditional candidates, never security or HE measurements.
All outputs are exclusive and every failed candidate is retained in the log.
"""
import argparse
from collections import Counter
from fractions import Fraction as F
from functools import lru_cache
import gzip
import hashlib
import itertools
import json
import math
from pathlib import Path
import struct
import sys
import time

CODE = Path(__file__).resolve().parent
ROOT = CODE.parent
sys.path.insert(0, str(CODE / 'public'))
from profile_certificate import branch_certificate, certify
from profile_selection import parameter_chain, contract_branch, branch_resources, to_go_config
from multipliers import design_profile
from selector import allocate_primes


def write_json(path, obj):
    with Path(path).open('x', encoding='utf-8') as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
        f.write('\n')


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_hashes():
    return {str(p.relative_to(ROOT)): digest(p) for p in sorted(CODE.rglob('*'))
            if p.is_file() and p.suffix in ('.py', '.go', '.mod', '.sum', '.json')
            and '__pycache__' not in p.parts}


def exact_input(seed, group, index, family):
    if family not in ('grow', 'reciprocal'):
        raise ValueError('unknown input family')
    if index < 0 or group < 0 or not 0 <= seed < 2**64:
        raise ValueError('invalid sample identity')
    x = ((F(1), F(2), F(3, 2))[index] if index < 3 else
         1 + F(int.from_bytes(hashlib.sha256(struct.pack('<QQQ', seed, group, index)).digest(), 'big'), 2**256))
    return x if family == 'grow' else 1/x


def task(scene, messages, precision, depth, family):
    if messages < 1 or not 1 <= precision <= 224 or depth not in (1, 2, 4, 6) or family not in ('grow', 'reciprocal'):
        raise ValueError('outside registered task domain')
    return {'id': f'{scene}_m{messages}_p{precision}_k{depth}_{family}',
            'scene': scene, 'messages': messages, 'precision_bits': precision,
            'depth': depth, 'input_family': family}


def matrix(spec):
    tasks = []
    for scene in ('small', 'capacity'):
        values = spec['scene_' + scene]
        for m, p, k, family in itertools.product(values['messages'], values['precision_bits'], values['depths'], spec['input_families']):
            tasks.append(task(scene, m, p, k, family))
    for extra in spec.get('extra_tasks', []):
        tasks.append(task(extra['scene'], extra['messages'], extra['precision_bits'], extra['depth'], extra['input_family']))
    if len({t['id'] for t in tasks}) != len(tasks):
        raise ValueError('duplicate registered tasks')
    return tasks


def validate_spec(spec):
    # These are audited implementation limits, not silently adjustable knobs.
    versions = {'pa-fixed-precision-design-v1': 32, 'pa-fixed-precision-design-v2': 64}
    if spec.get('schema') not in versions:
        raise ValueError('unregistered experiment design version')
    expected = {'scale_range': [24, 512],
                'max_Q_limbs': versions[spec['schema']], 'max_RNS_prime_bits': 60,
                'arithmetic_precision_bits': 1024, 'security_target_bits': 128,
                'formal_repeats': 5, 'plaintext_seed_base': 2026101300}
    for key, value in expected.items():
        if spec.get(key) != value:
            raise ValueError('design changes require implementation/certificate review: '+key)


def capacity(n, r, messages):
    if n < 32 or n & (n-1) or r not in (1, 2, 4) or messages < 1:
        raise ValueError('invalid capacity domain')
    slots = n//2
    useful = slots//r
    batches = (messages + useful - 1)//useful
    return {'N': n, 'classes': r, 'physical_slots_per_ciphertext': slots,
            'useful_capacity_per_ciphertext': useful, 'batches': batches,
            'effective_messages': messages, 'physical_slots_total': slots*batches,
            'structural_dummy_slots_total': (slots-useful)*batches,
            'unused_useful_slots_total': useful*batches-messages}


def boundary_tasks(t, candidates):
    points = {row['capacity']['useful_capacity_per_ciphertext']+d
              for row in candidates for d in (-1, 0, 1)}
    return [task('boundary', m, t['precision_bits'], t['depth'], t['input_family'])
            for m in sorted(points) if m > 0]


@lru_cache(None)
def unit(r, theta):
    if r not in (1, 2, 4) or theta < 0 or (r == 1 and theta != 0):
        raise ValueError('invalid class/transfer combination')
    if r == 1:
        return None
    # Only differences affect the unit: mean - target = (-(r-1)theta, theta,...).
    # Calling design_profile even at theta=0 preserves the dummy layout.
    return design_profile([0] + [-r*theta]*(r-1))


def question_for(t, r, theta):
    return {'id': t['id'], 'target_bits': [t['precision_bits']],
            'group_sizes': [t['messages']], 'depth': t['depth'],
            'dummy_ratio': r, 'dummy_budget': t['precision_bits']-r*theta}


def make_candidate(t, r, theta, n, offset, shape, slack, p_count, p_width, max_q_limbs=32):
    start = time.perf_counter()
    u = unit(r, theta)
    unit_time = time.perf_counter()-start
    q = question_for(t, r, theta)
    # This is a search seed, not the final error formula. Growth can amplify
    # absolute input error by about 2^(2^k-1) times 2^k.
    growth = (2**t['depth']-1) if t['input_family'] == 'grow' else 0
    base = max(24, t['precision_bits']-(r-1)*theta+growth+t['depth']+offset)
    if base > 512:
        raise ValueError('initial_scale_outside_search_domain')
    amplitude = F(2) if t['input_family'] == 'grow' else F(1)
    primes, counts, nominal, _ = parameter_chain(n, base, t['depth'], shape, slack, input_amplitude=amplitude, max_q_limbs=max_q_limbs)
    aux = allocate_primes(n, [p_width]*p_count, primes)
    m = None if u is None else {key: u[key] for key in
         ('period', 'coefficients', 'inverse_coefficients', 'embedding_intervals', 'construction_sha256')}
    design = {'groups': [0], 'slot_pattern': [0]+[-1]*(r-1) if r > 1 else [], 'multiplier': m}
    branch = contract_branch('direct', design, n, primes, aux, counts, base)
    certificate = branch_certificate(branch, 1024, q['target_bits'], t['depth'], amplitude)
    identity = json.dumps({'task': t, 'branch': branch, 'classes': r, 'theta': theta}, sort_keys=True).encode()
    return {'id': 'c'+hashlib.sha256(identity).hexdigest()[:24], 'task': t,
            'classes': r, 'theta': theta, 'nominal_dummy_precision_bits': q['dummy_budget'] if r > 1 else None,
            'branch': branch, 'capacity': capacity(n, r, t['messages']),
            'recipe': {'base': base, 'offset': offset, 'shape': shape, 'slack': slack, 'P_count': p_count, 'P_width': p_width},
            'unit': {'coefficient_bits': u['coefficient_bits'] if u else 1,
                     'inverse_coefficient_bits': max(abs(int(x)).bit_length() for x in u['inverse_coefficients']) if u else 1,
                     'actual_log2_weights': u['actual_log2_weights_display'] if u else [0.0],
                     'construction_or_cache_seconds': unit_time},
            'Q_bits_ceiling': (math.prod(primes)-1).bit_length(), 'Q_prime_count': len(primes),
            'resources': branch_resources(branch, q['group_sizes'], r > 1),
            'conditional_correctness': certificate['pass'], 'reasons': certificate['reasons'],
            'group_errors': certificate['group_errors'],
            'max_range_ratio_upper': str(max(map(F, certificate['range_ratios_upper']))),
            'security_status': 'not_estimated', 'HE_executions': 0}


def config_for(row, repeat=1):
    t = row['task']
    q = question_for(t, row['classes'], row['theta'])
    cfg = to_go_config(q, 'r'+str(row['classes']), [row], repeat)
    cfg.update(schema='pa-fixed-precision-experiment-v1', id=row['id']+'_rep'+str(repeat),
               input_family=t['input_family'], plaintext_seed=str(2026101300+repeat))
    return cfg


def frontier(rows):
    # Security inputs differ by N and QP. Keep each N/r/theta cell separately.
    # A candidate with smaller Q but larger P must not erase a securer candidate.
    groups = {}
    def vector(x):
        z = x['resources']
        return (x['Q_bits_ceiling'], x['Q_prime_count'], z['QP_log2_ceiling'],
                z['square_Q_words'], z['ks_transform_word_proxy'], z['relin_bytes'])
    for row in sorted(rows, key=lambda x: (vector(x), x['id'])):
        key = (row['branch']['N'], row['classes'], row['theta'])
        kept = groups.setdefault(key, [])
        v = vector(row)
        if any(all(a <= b for a, b in zip(vector(old), v)) for old in kept):
            continue
        kept[:] = [old for old in kept if not all(a <= b for a, b in zip(v, vector(old)))]
        kept.append(row)
    return [row for values in groups.values() for row in values]


def scan(t, spec, out, pilot=False, classes=None, dimensions=None, thetas=None, offsets=None):
    validate_spec(spec)
    out = Path(out)
    out.mkdir(parents=True, exist_ok=False)
    # A small public pipeline check, not a substitute for the registered family.
    family = {'classes': classes or spec['class_counts'], 'N': dimensions or ([8192] if pilot else spec['N']),
              'theta': thetas if thetas is not None else ([0, 20, 40] if pilot else spec['theta']),
              'offsets': offsets or ([32, 48] if pilot else spec['scale_offsets']),
              'shapes': ['flat'] if pilot else spec['shapes'],
              'slacks': [2] if pilot else spec['output_slack_bits'],
              'P_counts': [2, 4] if pilot else spec['P_counts'], 'P_widths': spec['P_prime_widths']}
    write_json(out/'registration.json', {'task': t, 'search_family': family, 'pilot_only': pilot,
               'source_sha256': source_hashes(), 'security_estimated': False, 'HE_executions': 0})
    cells, failures, count, passes = {}, Counter(), 0, 0
    with gzip.open(out/'all_candidates.jsonl.gz', 'xt') as stream:
        for r in family['classes']:
            theta_values = [0] if r == 1 else family['theta']
            for theta, n, offset, shape, slack, pc, pw in itertools.product(theta_values, family['N'], family['offsets'], family['shapes'], family['slacks'], family['P_counts'], family['P_widths']):
                recipe = dict(classes=r, theta=theta, N=n, offset=offset, shape=shape, slack=slack, P_count=pc, P_width=pw)
                try:
                    row = make_candidate(t, r, theta, n, offset, shape, slack, pc, pw, spec['max_Q_limbs'])
                except (ValueError, ArithmeticError) as e:
                    row = {'recipe': recipe, 'conditional_correctness': False, 'reasons': ['public_generation:'+str(e)], 'HE_executions': 0}
                count += 1
                stream.write(json.dumps(row, separators=(',', ':'))+'\n')
                failures.update(row['reasons'])
                if row['conditional_correctness']:
                    passes += 1
                    cell = (n, r, theta)
                    cells[cell] = frontier(cells.get(cell, [])+[row])
                if count % 100 == 0:
                    stream.flush()
                    print(f'{t["id"]}: {count} public candidates, {passes} conditional passes', flush=True)
    fronts = [row for cell in cells.values() for row in cell]
    top_theta = max(family['theta']) if family['theta'] else 0
    theta_boundary = []
    for n, r in itertools.product(family['N'], family['classes']):
        cell = [x for x in fronts if x['branch']['N'] == n and x['classes'] == r]
        if r > 1 and cell:
            best = min(x['Q_bits_ceiling'] for x in cell)
            if any(x['theta'] == top_theta and x['Q_bits_ceiling'] == best for x in cell):
                theta_boundary.append({'N': n, 'classes': r, 'theta': top_theta})
    result = {'schema': 'pa-cost-public-search-v1', 'task': t, 'pilot_only': pilot,
              'candidate_count': count, 'conditional_pass_count': passes, 'failure_counts': dict(failures),
              'frontier': fronts, 'theta_upper_boundary_winners': theta_boundary,
              'search_domain_only': True, 'security_estimated': False, 'HE_executions': 0}
    write_json(out/'summary.json', result)
    configs = out/'configs'; configs.mkdir()
    for row in fronts:
        write_json(configs/(row['id']+'.json'), config_for(row))
    print(json.dumps({k: v for k, v in result.items() if k not in ('frontier',)}, ensure_ascii=False), flush=True)
    return result


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--spec', default=str(ROOT/'code/design/experiment_matrix.json'))
    sub = ap.add_subparsers(dest='command', required=True)
    m = sub.add_parser('matrix'); m.add_argument('--out', required=True)
    s = sub.add_parser('scan')
    s.add_argument('--task-id', required=True); s.add_argument('--out', required=True)
    s.add_argument('--pilot', action='store_true')
    s.add_argument('--classes', nargs='+', type=int, choices=[1, 2, 4])
    s.add_argument('--N', nargs='+', type=int, choices=[4096, 8192, 16384, 32768, 65536, 131072])
    s.add_argument('--theta', nargs='+', type=int)
    s.add_argument('--offsets', nargs='+', type=int)
    b = sub.add_parser('boundaries'); b.add_argument('--summary', required=True); b.add_argument('--out', required=True)
    c = sub.add_parser('certify'); c.add_argument('--plan', required=True); c.add_argument('--out', required=True)
    args = ap.parse_args(); spec = json.loads(Path(args.spec).read_text())
    validate_spec(spec)
    if args.command == 'matrix':
        write_json(args.out, {'schema': 'pa-cost-tasks-v1', 'design_sha256': digest(args.spec), 'tasks': matrix(spec)})
    elif args.command == 'scan':
        selected = next((t for t in matrix(spec) if t['id'] == args.task_id), None)
        if selected is None:
            raise ValueError('task is not in the supplied registered design')
        scan(selected, spec, args.out, args.pilot, args.classes, args.N, args.theta, args.offsets)
    elif args.command == 'boundaries':
        data = json.loads(Path(args.summary).read_text())
        write_json(args.out, {'source_sha256': digest(args.summary), 'tasks': boundary_tasks(data['task'], data['frontier']),
                             'status': 'proposed_boundary_tasks_require_registration_in_next_search_stage'})
    else:
        plan = json.loads(Path(args.plan).read_text()); result = certify(plan)
        result.update(plan_sha256=digest(args.plan), source_sha256=source_hashes())
        write_json(args.out, result)


if __name__ == '__main__':
    if hasattr(sys, 'set_int_max_str_digits'):
        sys.set_int_max_str_digits(0)  # Exact references at k=6 exceed the CPython text guard.
    main()
