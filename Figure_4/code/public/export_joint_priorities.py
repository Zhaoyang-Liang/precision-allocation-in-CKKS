"""Export pre-timing public priorities per N, before security filtering.

Keep computation proxy, key storage, and smallest QP priorities separately:
minimizing the proxy alone may choose many P primes and force a larger N.
No security or time optimum is inferred from this finite representative pool.
"""
import argparse
import hashlib
import json
from pathlib import Path

from group_selection import limited_representatives
from profile_selection import to_go_config


def export(summary_path,out):
    source=Path(summary_path);summary=json.loads(source.read_text());out=Path(out);out.mkdir()
    rows=[]
    for block in summary['results']:
        candidates=[r for front in block['fronts_by_N'].values() for r in front]
        for entry in limited_representatives(candidates):
            r=entry['row'];config=to_go_config(summary['question'],block['method'],[r])
            tag=hashlib.sha256(r['id'].encode()).hexdigest()[:12]
            filename=f"{block['method']}_N{r['branch']['N']}_{tag}_public_config.json"
            with (out/filename).open('x') as f:json.dump(config,f,indent=2);f.write('\n')
            rows.append({'config':filename,'candidate_id':r['id'],'method':block['method'],
                         'public_priorities':entry['priorities'],'resources':r['resources'],
                         'conditional_correctness':r['conditional_correctness']})
    result={'schema':'new-joint-presecurity-priorities-v1','source_sha256':hashlib.sha256(source.read_bytes()).hexdigest(),
            'question':summary['question'],'selection_before_any_HE':True,'HE_executions':0,
            'priorities':['square-plus-switch structural proxy','key storage','QP ceiling'],
            'scope':'finite representative choices per N, not a global or measured-time optimum','candidates':rows}
    with (out/'priorities.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print('exported',len(rows),'public pre-security priorities; HE executions 0')


if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('summary');a.add_argument('out');v=a.parse_args();export(v.summary,v.out)
