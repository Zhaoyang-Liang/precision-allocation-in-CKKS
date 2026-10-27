"""Audit and summarize the bootstrap-only jobs; keep every measured input."""
from pathlib import Path
import json
import math
import statistics as stats

ROOT = Path(__file__).resolve().parents[1] / "result"
OUT = ROOT / "reproduced"
OUT.mkdir(exist_ok=True)
CASES = ['direct16', 'leaf16-15', 'direct13', 'leaf17-13', 'leaf17-15', 'leaf16-14']
LEVELS = dict(zip(CASES, [13, 13, 2, 1, 13, 1]))
manifest = [line.split() for line in (ROOT / 'formal-jobs.tsv').read_text().splitlines()]
assert len(manifest) == 18
summary = {}
verified = []
for case in CASES:
    jobs = [row for row in manifest if row[1] == case]
    assert len(jobs) == 3 and {row[2] for row in jobs} == {'1', '2', '3'}
    runs, trials = [], []
    for job, _, rep, seed in jobs:
        r = json.loads((ROOT / 'raw_runs' / ('run-' + job) / 'result.json').read_text())
        c = r['Config']
        assert r['Status'] == 'executed' and not r['Error'] and r['CasesFailed'] == 0, (case, job)
        assert c['Seed'] == int(seed) and not c['CheckSquare']
        assert c.get('ChainLength', 0) == 0 and c.get('InverseSqrtIterations', 0) == 0
        assert not c.get('Statistics') and not c.get('ApplicationBeforeReturn')
        assert not c.get('CalibrateApplicationScale')
        assert r.get('ApplicationKeyBytes', 0) == r.get('FrontendKeyBytes', 0) == 0
        assert len(r['Trials']) == (16 if case == 'direct13' else 3)
        key_bytes = sum(r.get(k, 0) for k in ['MainKeyBytes', 'EntryKeyBytes', 'SSEKeyBytes', 'LiftKeyBytes', 'ReturnKeyBytes'])
        runs.append(dict(job=job, host=r['Host'], keygen=r['KeygenSeconds'], key_bytes=key_bytes))
        for t in r['Trials']:
            assert not t['Error'] and t.get('PairedCiphertextsEqual', t.get('SerialCiphertextsEqual')), (case, job, t['Index'])
            assert t.get('RefreshedBranches', 1) == 1
            assert t.get('ApplicationSeconds', 0) == t.get('SquareSeconds', 0) == 0
            assert t.get('Frontend', {}).get('OnlineSeconds', 0) == 0
            assert t.get('InverseSqrt', {}).get('ArithmeticSeconds', 0) == 0
            assert t.get('ApplicationChain', {}).get('ArithmeticSeconds', 0) == 0
            branches = [b for b in t.get('Branches', []) if not b.get('Skipped')]
            if case == 'leaf17-13':
                assert t['Pruned'] and t['BranchCount'] == 16
                assert sum(bool(b['Skipped']) for b in t['Branches']) == 15
                bits = t['Output']['DataErrorBits']
                output = dict(Level=t['OutputLevel'], LogQ=t['OutputLogQ'], LogScale=t['OutputLogScale'])
                stages = {k: sum(b[k] for b in branches) for k in ('ReadoutSeconds', 'EvalModSeconds')}
            else:
                bits = t['OutputMetrics']['MaxErrorBits']
                output = t['Output']
                stages = {k: sum(b[k] for b in branches) for k in ('StCSeconds', 'SSESeconds', 'LiftTraceSeconds', 'CtSSeconds', 'EvalModSeconds')}
                if case == 'direct13':
                    stages.update(ReadoutSeconds=t['ReadoutSeconds'], EvalModSeconds=t['EvalModSeconds'])
                else:
                    if not c['NoRS']:
                        assert r['ReturnKeyLevel'] == c['OutputLevel']
                    else:
                        assert r['ReturnKeyBytes'] == 0
                    assert t['OutputLocation'] == 'top-ring bootstrap output before application'
                    assert c['ActiveBranches'] == 1 and not c['RefreshDummy']
                    assert len(t['SkippedBranchIndices'] or []) == r['Branches'] - 1
            assert output['Level'] == LEVELS[case]
            assert math.isfinite(bits)
            target = 1 if case in ('direct13', 'leaf17-13') else 20
            # Record failed precision targets as evidence rather than discarding them.
            verified.append(dict(case=case, job=job, trial=t['Index'], output_level=output['Level'], bits=bits, target_bits=target, meets_target=bits >= target))
            serial, parallel = t['SerialOnlineSeconds'], t['ParallelOnlineSeconds']
            assert math.isfinite(serial) and serial > 0 and math.isfinite(parallel) and parallel > 0
            trials.append(dict(job=job, index=t['Index'], serial=serial, parallel=parallel, bits=bits, output=output,
                               entry=t.get('EntrySplitSeconds', t.get('EntrySeconds', 0)),
                               return_time=t.get('MergeReturnSeconds', 0), stages=stages))
    assert len({r['key_bytes'] for r in runs}) == 1
    summary[case] = dict(runs=runs, trials=trials, summary=dict(
        keys=len(runs), trials=len(trials), serial_mean=stats.mean(t['serial'] for t in trials),
        parallel_mean=stats.mean(t['parallel'] for t in trials),
        serial_sd=stats.stdev(t['serial'] for t in trials), parallel_sd=stats.stdev(t['parallel'] for t in trials),
        min_bits=min(t['bits'] for t in trials), keygen_mean=stats.mean(r['keygen'] for r in runs),
        key_GiB=runs[0]['key_bytes'] / 2**30))
assert len(verified) == 93
assert summary == json.loads((ROOT / 'summary.json').read_text()), 'Archived summary mismatch'
failures = [v for v in verified if not v['meets_target']]
for case in CASES:
    print(case, json.dumps(summary[case]['summary']))
print(f'{len(verified)} exact serial/parallel pairs; {len(failures)} precision target failures.')
