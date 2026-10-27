#!/usr/bin/env python3
"""Export compact measured/audited CSVs; retain ciphertexts on the server."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import statistics

ROOT = Path(__file__).resolve().parents[2]


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as f:
        for block in iter(lambda: f.read(1024*1024), b''):
            h.update(block)
    return h.hexdigest()


def write_csv(path, rows):
    if not rows:
        return
    fields = list(dict.fromkeys(k for row in rows for k in row))
    with path.open('x', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader(); writer.writerows(rows)


def export(directories, out, hash_raw=False):
    out = Path(out).resolve()
    out.mkdir(parents=True, exist_ok=False)
    runs, summaries, configs, failures, raw_files, units = [], [], [], [], [], []
    campaigns_seen = set()
    for directory in directories:
        directory = Path(directory).resolve()
        frozen, measured = directory/'frozen', directory/'measured'
        if not (frozen/'registry.json').exists():
            failures.append({'campaign': str(directory), 'reason': 'missing_frozen_registry'})
            continue
        reg = json.loads((frozen/'registry.json').read_text())
        identity = (reg['pilot_only'], reg['selected'][0]['candidate']['task']['id'])
        if identity in campaigns_seen:
            raise ValueError('Duplicate campaign in this export')
        campaigns_seen.add(identity)
        env = json.loads((measured/'environment.json').read_text()) if (measured/'environment.json').exists() else {}
        if env and env['registry_sha256'] != digest(frozen/'registry.json'):
            raise ValueError('Measured registry identity mismatch')
        if env and env['binary_sha256'] != reg['binary_sha256']:
            raise ValueError('Measured binary identity mismatch')
        selected = {s['candidate']['id']: s['candidate'] for s in reg['selected']}
        metadata = {}
        for cid, row in selected.items():
            b, t, cap, resources = row['branch'], row['task'], row['capacity'], row['resources']
            cert = json.loads((frozen/'evidence'/(cid+'.certificate.json')).read_text())
            sec = json.loads((frozen/'evidence'/(cid+'.security.json')).read_text())
            matches = [s for s in sec['cases'] if s['N'] == b['N'] and s['Q'] == b['Q'] and s['P'] == b['P'] and s['all_three_attacks_pass']]
            if not matches or not cert['all_branches_pass']:
                raise ValueError('Missing exact security or correctness evidence')
            work_factors = [float(a['log2_rop']) for a in matches[0]['attacks'].values()]
            m = dict(task_id=t['id'], scene=t['scene'], messages=t['messages'], target_bits=t['precision_bits'],
                depth=t['depth'], input_family=t['input_family'], candidate_id=cid, classes=row['classes'], theta=row['theta'],
                nominal_dummy_bits=row['nominal_dummy_precision_bits'], actual_useful_gain_bits=-row['unit']['actual_log2_weights'][0],
                nominal_mean_precision_bits=t['precision_bits']-(row['classes']-1)*row['theta'],
                actual_log2_weights='|'.join(map(str,row['unit']['actual_log2_weights'])),
                unit_coefficient_bits=row['unit']['coefficient_bits'], inverse_coefficient_bits=row['unit']['inverse_coefficient_bits'],
                N=b['N'], Q_bits=row['Q_bits_ceiling'], Q_count=len(b['Q']), P_count=len(b['P']),
                QP_bits=resources['QP_log2_ceiling'], initial_scale_bits=b['initial_scale_bits'],
                shape=row['recipe']['shape'], P_width=row['recipe']['P_width'], output_slack=row['recipe']['slack'],
                rescale_counts='|'.join(map(str,b['rescale_counts'])), Q='|'.join(b['Q']), P='|'.join(b['P']),
                batches=cap['batches'], useful_capacity=cap['useful_capacity_per_ciphertext'],
                structural_dummy_slots=cap['structural_dummy_slots_total'], unused_useful_slots=cap['unused_useful_slots_total'],
                certified_precision_bits=row['group_errors']['0']['bits_display'], security_min_bits=min(work_factors),
                priorities='|'.join(row.get('selection',{}).get('priorities',[])),
                pilot_only=reg['pilot_only'], node=env.get('node'), job_id=env.get('slurm_job_id'),
                binary_sha256=reg['binary_sha256'], campaign=str(directory.relative_to(ROOT)))
            configs.append(m); metadata[cid] = m
        unit_file = directory/'unit_preparation/unit_preparation.csv'
        if unit_file.exists():
            with unit_file.open() as f:
                for row in csv.DictReader(f):
                    units.append(dict(metadata[row['candidate_id']], construction_repeat=int(row['repeat']),
                                      cold_construction_ms=float(row['construction_ms'])))
        grouped = {cid: [] for cid in selected}
        for i, item in enumerate(reg['schedule']):
            cid, repeat = item['candidate_id'], item['repeat']
            label = f'{i:03d}_{cid}_r{repeat}'
            path = measured/label
            audit_path = measured/(label+'.audit.json')
            if not (path/'result.json').exists() or not audit_path.exists():
                failures.append({'campaign': str(directory.relative_to(ROOT)), 'candidate_id': cid, 'repeat': repeat,
                                 'reason': 'missing_result_or_independent_audit'})
                continue
            result, audit = json.loads((path/'result.json').read_text()), json.loads(audit_path.read_text())
            config_hash = digest(path/'config.json')
            if config_hash != result['config_sha256'] or config_hash != digest(frozen/item['config']):
                raise ValueError('Result configuration identity mismatch')
            if result['contract_sha256'] != audit['contract_sha256'] or int(result['online']['wall_ns']) != audit['wall_ns']:
                raise ValueError('Audit identity/timing mismatch')
            if not audit['all_checks_pass'] or not audit['business_accuracy_pass'] or result['status'] != 'completed':
                failures.append({'campaign': str(directory.relative_to(ROOT)), 'candidate_id': cid, 'repeat': repeat,
                                 'reason': 'record_or_business_accuracy_failed'})
                continue
            preparation = result['preparation']; verification = result['verification']
            m = dict(metadata[cid], repeat=repeat, measurement_order=i, plaintext_seed=result['plaintext_seed'],
                all_effective_results_pass=True, actual_precision_bits=min(audit['precision_bits_display']),
                online_ns=int(audit['wall_ns']), online_ms=audit['wall_ns']/1e6,
                peak_rss_bytes=int(result['process_peak_rss_bytes']),
                output_payload_bytes=audit['output_payload_bytes'], output_serialized_bytes=audit['output_serialized_bytes'],
                relin_payload_bytes=audit['evaluation_key_payload_bytes'], public_key_payload_bytes=audit['public_key_payload_bytes'],
                total_process_work_ms=int(result['total_process_work_ns'])/1e6,
                reference_generation_ms=int(result['reference_generation_ns'])/1e6,
                run_path=str(path.relative_to(ROOT)), result_sha256=digest(path/'result.json'), audit_sha256=digest(audit_path))
            m.update({'preparation_'+k.removesuffix('_ns')+'_ms': int(v)/1e6 for k,v in preparation.items()})
            m.update({'verification_'+k.removesuffix('_ns')+'_ms': int(v)/1e6 for k,v in verification.items() if k.endswith('_ns')})
            runs.append(m); grouped[cid].append(m)
        for cid, values in grouped.items():
            if len(values) != 5 or {r['repeat'] for r in values} != set(range(1,6)):
                continue
            times = [r['online_ms'] for r in values]
            summaries.append(dict(metadata[cid], repeat_count=5, median_online_ms=statistics.median(times),
                min_online_ms=min(times), max_online_ms=max(times), mean_online_ms=statistics.mean(times),
                worst_actual_precision_bits=min(r['actual_precision_bits'] for r in values),
                peak_rss_bytes_max=max(r['peak_rss_bytes'] for r in values), all_five_runs_pass=True))
        if hash_raw:
            for path in sorted(directory.rglob('*')):
                if path.is_file():
                    raw_files.append({'path': str(path.relative_to(ROOT)), 'bytes': path.stat().st_size, 'sha256': digest(path)})
    write_csv(out/'runs.csv', runs)
    write_csv(out/'summary.csv', summaries)
    write_csv(out/'configurations.csv', configs)
    write_csv(out/'unit_preparation.csv', units)
    write_csv(out/'incomplete_or_failed.csv', failures)
    if hash_raw:
        write_csv(out/'remote_raw_manifest.csv', raw_files)
    manifest = {'schema': 'pa07-compact-measurements-v1', 'campaigns': len(campaigns_seen), 'audited_runs': len(runs),
        'complete_five_repeat_configurations': len(summaries), 'selected_configurations': len(configs),
        'missing_or_failed_runs': len(failures), 'all_selected_measurements_complete': not failures and len(configs)==len(summaries),
        'raw_files_hashed': len(raw_files), 'raw_bytes_hashed': sum(r['bytes'] for r in raw_files),
        'script_sha256': digest(__file__), 'scope': 'Only full five-repeat groups contribute performance summaries; incomplete records are listed separately.',
        'files': {p.name: digest(p) for p in out.glob('*.csv')}}
    with (out/'manifest.json').open('x') as f:
        json.dump(manifest, f, indent=2); f.write('\n')
    print(json.dumps(manifest), flush=True)


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--stage', action='append', default=[])
    ap.add_argument('--campaign', action='append', default=[])
    ap.add_argument('--out', required=True)
    ap.add_argument('--hash-raw', action='store_true')
    args = ap.parse_args()
    directories = list(map(Path,args.campaign))
    for stage in args.stage:
        directories.extend(p for p in sorted(Path(stage).iterdir()) if p.is_dir() and (p/'frozen').exists())
    if not directories:
        raise ValueError('No campaigns found')
    export(directories, args.out, args.hash_raw)
