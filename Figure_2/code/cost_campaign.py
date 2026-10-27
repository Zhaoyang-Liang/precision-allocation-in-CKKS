"""Freeze and execute five-repeat campaigns, after real security evidence.

Manifest candidates reference public search records and real estimator files.
Neither missing attacks nor a failed certificate can start HE execution.
"""
import argparse
from collections import defaultdict
from copy import deepcopy
from fractions import Fraction as F
import json
import os
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time

from cost_experiment import config_for, digest, source_hashes, write_json
from profile_certificate import certify
from audit_profile_results import audit, error_bits


def run_command(command, logfile):
    with Path(logfile).open('x') as f:
        result = subprocess.run(list(map(str, command)), stdout=f, stderr=subprocess.STDOUT,
                                env=dict(os.environ, GOMAXPROCS='1', PYTHONINTMAXSTRDIGITS='0'))
    if result.returncode:
        raise RuntimeError(f'command failed ({result.returncode}); retained log: {logfile}')


def freeze(manifest_path, binary, out):
    manifest_path, binary, out = Path(manifest_path).resolve(), Path(binary).resolve(), Path(out).resolve()
    manifest = json.loads(manifest_path.read_text())
    if manifest.get('schema') != 'pa-cost-selection-v1' or not manifest.get('candidates'):
        raise ValueError('explicit nonempty selection manifest required')
    out.mkdir(parents=True, exist_ok=False)
    (out/'evidence').mkdir(); (out/'configs').mkdir(); (out/'preflight').mkdir()
    write_json(out/'selection.json', manifest)
    selected, ids, task_identity = [], set(), None
    for item in manifest['candidates']:
        summary_path = (manifest_path.parent/item['summary']).resolve()
        summary = json.loads(summary_path.read_text())
        if summary.get('pilot_only') and not manifest.get('pilot_only'):
            raise ValueError('pilot search cannot silently become a formal selection')
        row = next(x for x in summary['frontier'] if x['id'] == item['candidate_id'])
        if not row['conditional_correctness'] or row['id'] in ids:
            raise ValueError('uncertified or duplicate candidate')
        ids.add(row['id'])
        if task_identity is None:
            task_identity = row['task']
        if row['task'] != task_identity:
            raise ValueError('one campaign compares exactly the same task')
        sid = row['id']
        security_path = (manifest_path.parent/item['security_file']).resolve()
        security_data = security_path.read_bytes()
        security_dest = out/'evidence'/(sid+'.security.json')
        security_dest.write_bytes(security_data)
        cfg = config_for(row)
        write_json(out/'configs'/(sid+'.public.json'), cfg)
        plan_path = out/'evidence'/(sid+'.plan.json')
        run_command([binary, '-mode', 'plan', '-config', out/'configs'/(sid+'.public.json'), '-out', plan_path], out/'preflight'/(sid+'.plan.log'))
        plan = json.loads(plan_path.read_text()); cert = certify(plan)
        cert.update(source_sha256=source_hashes(), plan_sha256=digest(plan_path))
        certificate_path = out/'evidence'/(sid+'.certificate.json')
        write_json(certificate_path, cert)
        if not cert['all_branches_pass']:
            raise ValueError('backend plan does not obtain the conditional certificate')
        cfg.update(certification_status='conditional_certified', certificate_file='../evidence/'+certificate_path.name)
        cfg['branches'][0].update(security_file='../evidence/'+security_dest.name, security_sha256=digest(security_dest))
        config_paths = []
        for repeat in range(1, 6):
            c = deepcopy(cfg)
            c.update(id=sid+'_rep'+str(repeat), repeat=repeat, plaintext_seed=str(2026101300+repeat))
            path = out/'configs'/(c['id']+'.json')
            write_json(path, c)
            # Includes exact Q/P security match, family counts and memory guard.
            run_command([binary, '-mode', 'check', '-config', path], out/'preflight'/(c['id']+'.check.log'))
            config_paths.append(str(path.relative_to(out)))
        selected.append({'candidate': row, 'summary_sha256': digest(summary_path), 'configs': config_paths})
    # Rotate the method order each repeat; fresh process/key generation every run.
    schedule = []
    for repeat in range(5):
        order = selected[repeat % len(selected):]+selected[:repeat % len(selected)]
        schedule.extend({'candidate_id': v['candidate']['id'], 'repeat': repeat+1, 'config': v['configs'][repeat]} for v in order)
    files = {str(p.relative_to(out)): digest(p) for p in out.rglob('*') if p.is_file()}
    registry = {'schema': 'pa-cost-frozen-campaign-v1', 'pilot_only': manifest.get('pilot_only', False),
                'binary_sha256': digest(binary), 'source_sha256': source_hashes(),
                'files_sha256': files, 'selected': selected, 'schedule': schedule,
                'repeat_count': 5, 'sampled_event_union_upper': f'{len(schedule)} * 2^-159',
                'scope': 'One N per run; union bound over scheduled runs, not a claim over all future searches.'}
    write_json(out/'registry.json', registry)
    return registry


def summarize(audits):
    if len(audits) != 5 or {x['repeat'] for x in audits} != set(range(1, 6)):
        raise ValueError('five distinct planned repeats required')
    for field in ('contract_sha256', 'question_id', 'effective_results'):
        if len({x[field] for x in audits}) != 1:
            raise ValueError('mixed tasks or parameters')
    if not all(x['all_checks_pass'] and x['business_accuracy_pass'] for x in audits):
        raise ValueError('failed run cannot contribute to a speedup claim')
    times = [x['wall_ns'] for x in audits]
    worst = [max(F(x['error_squared_max_by_group'][g]) for x in audits)
             for g in range(len(audits[0]['error_squared_max_by_group']))]
    return {'repeat_count': 5, 'wall_ns_each': times, 'median_wall_ns': statistics.median(times),
            'min_wall_ns': min(times), 'max_wall_ns': max(times),
            'worst_precision_bits': [error_bits(x) for x in worst],
            'all_effective_results_pass': True, 'effective_messages': audits[0]['effective_results'],
            'error_squared_max_by_group': list(map(str, worst))}


def execute(campaign, binary, out):
    campaign, binary, out = Path(campaign).resolve(), Path(binary).resolve(), Path(out).resolve()
    registry_path = campaign/'registry.json'
    reg = json.loads(registry_path.read_text())
    if reg['schema'] != 'pa-cost-frozen-campaign-v1' or digest(binary) != reg['binary_sha256']:
        raise ValueError('campaign or executable mismatch')
    if source_hashes() != reg['source_sha256']:
        raise ValueError('source changed after registration; freeze a new campaign')
    for name, sha in reg['files_sha256'].items():
        if digest(campaign/name) != sha:
            raise ValueError('frozen evidence/config changed: '+name)
    out.mkdir(parents=True, exist_ok=False)
    write_json(out/'environment.json', {'platform': platform.platform(), 'node': platform.node(),
               'cpu': platform.processor(), 'slurm_job_id': os.environ.get('SLURM_JOB_ID'),
               'registry_sha256': digest(registry_path), 'binary_sha256': digest(binary),
               'pilot_only': reg['pilot_only'], 'gomaxprocs': 1})
    groups = defaultdict(list)
    for order, item in enumerate(reg['schedule']):
        label = f'{order:03d}_{item["candidate_id"]}_r{item["repeat"]}'
        write_json(out/(label+'.started.json'), {'time_unix': time.time(), **item})
        run_command([binary, '-mode', 'run', '-config', campaign/item['config'], '-out', out/label], out/(label+'.log'))
        result = audit(out/label)
        write_json(out/(label+'.audit.json'), result)
        if not result['business_accuracy_pass']:
            raise RuntimeError('accuracy failed; original output retained, no automatic rerun')
        groups[item['candidate_id']].append(result)
    results = {key: summarize(value) for key, value in groups.items()}
    write_json(out/'summary.json', {'schema': 'pa-cost-measurement-v1', 'pilot_only': reg['pilot_only'],
               'candidates': results, 'registry_sha256': digest(registry_path),
               'timing_scope': 'Measured total online work for all M messages; preparation and diagnostics separate.'})


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    subs = ap.add_subparsers(dest='command', required=True)
    f = subs.add_parser('freeze'); f.add_argument('--selection', required=True)
    e = subs.add_parser('run'); e.add_argument('--campaign', required=True)
    for parser in (f, e):
        parser.add_argument('--binary', required=True); parser.add_argument('--out', required=True)
    args = ap.parse_args()
    if args.command == 'freeze':
        freeze(args.selection, args.binary, args.out)
    else:
        execute(args.campaign, args.binary, args.out)


if __name__ == '__main__':
    if hasattr(sys, 'set_int_max_str_digits'):
        sys.set_int_max_str_digits(0)
    main()
