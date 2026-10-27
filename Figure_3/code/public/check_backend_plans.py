"""Cross-check exported Go metadata against exact Python certificates, no HE."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import time

from profile_certificate import certify
from group_selection import combined_resources

ROOT=Path(__file__).resolve().parents[1]


def main():
    ap=argparse.ArgumentParser();ap.add_argument('directory');args=ap.parse_args()
    directory=Path(args.directory);record=[]
    for config in sorted(directory.glob('*_public_config.json')):
        plan=config.with_name(config.stem+'_plan.json')
        certificate=config.with_name(config.stem+'_certificate.json')
        if plan.exists() or certificate.exists():raise FileExistsError(plan)
        start=time.monotonic()
        command=[str(ROOT/'profilebench'),'-mode','plan','-config',str(config),'-out',str(plan)]
        result=subprocess.run(command,capture_output=True,text=True)
        row={'config':config.name,'command':command,'exit_code':result.returncode,
             'stdout':result.stdout,'stderr':result.stderr,'public_wall_seconds':time.monotonic()-start}
        record.append(row)
        if result.returncode==0:
            actual=json.loads(plan.read_text())
            cert=certify(actual)
            expected=combined_resources([{'branch':b} for b in actual['contract']['branches']],actual['contract']['group_sizes'])
            for a,b in (('relin_bytes','shared_relin_coefficient_payload_bytes'),
                        ('public_key_bytes','shared_public_key_coefficient_payload_bytes'),
                        ('preflight_memory_guard_bytes','preflight_memory_guard_bytes')):
                if expected[a]!=int(actual[b]):raise ValueError('shared backend resource mismatch '+a)
            if len(actual['key_family_plan'])!=expected['key_family_count']:
                raise ValueError('shared backend family count mismatch')
            row['shared_resource_crosscheck']=True
            cert['plan_sha256']=hashlib.sha256(plan.read_bytes()).hexdigest()
            with certificate.open('x') as f:json.dump(cert,f,indent=2);f.write('\n')
            row['conditional_correctness']=cert['all_branches_pass']
            row['contract_sha256']=cert['contract_sha256']
        print(config.name,row.get('conditional_correctness',False),flush=True)
    summary={'schema':'backend-plan-exact-crosscheck-v1','records':record,
             'HE_executions':0,'security_estimated':False,
             'all_pass':bool(record) and all(r.get('conditional_correctness',False) for r in record)}
    with (directory/'backend_crosscheck.json').open('x') as f:json.dump(summary,f,indent=2);f.write('\n')
    if not summary['all_pass']:raise SystemExit(1)


if __name__=='__main__':main()
