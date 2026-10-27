"""One-bit PUBLIC scale boundary refinement, before any HE measurements.

Both representations use the same +/-3-bit rule around their coarse surviving
recipes. Rebuild exact primes and metadata; a numeric bit change is not assumed
to preserve the certificate. All failed attempts remain in the output stream.
"""
import argparse
from fractions import Fraction as F
import gzip
import hashlib
import json
from pathlib import Path

from profile_selection import (branch_design,parameter_chain,contract_branch,
                              branch_resources,pareto,to_go_config)
from profile_certificate import branch_certificate
from selector import allocate_primes


def refine(summary,stream):
    q=summary['question'];results=[]
    for block in summary['results']:
        allocated=block['method']=='allocated';groups=tuple(block['groups'])
        design=branch_design(q,groups,allocated);seen=set();passing=[];counts={}
        # New summaries carry recipes explicitly. Historical pilot records are
        # not silently interpreted or upgraded to the new sampling contract.
        for rows in block['fronts_by_N'].values():
            for row in rows:
                recipe=row['parameter_recipe'];n=row['branch']['N']
                for delta in range(-3,4):
                    r=dict(recipe,base=recipe['base']+delta)
                    key=(n,*[r[k] for k in ('base','shape','slack','p_count','p_width')])
                    if key in seen:continue
                    seen.add(key)
                    if r['base']<24 or r['base']>512:continue
                    record={'parent':row['id'],'parameter_recipe':r,'N':n,'security_estimated':False,'HE_executions':0}
                    try:
                        primes,rescales,nominal,_=parameter_chain(n,r['base'],q['depth'],r['shape'],r['slack'])
                        aux=allocate_primes(n,[r['p_width']]*r['p_count'],primes)
                        b=contract_branch(row['branch']['id'],design,n,primes,aux,rescales,nominal[0])
                        cert=branch_certificate(b,1024,q['target_bits'],q['depth'])
                        identity=hashlib.sha256(json.dumps(b,sort_keys=True,separators=(',',':')).encode()).hexdigest()[:20]
                        record.update({'id':'refined_'+identity,'branch':b,'shape':r['shape'],'nominal_scales':nominal,
                            'resources':branch_resources(b,q['group_sizes'],design['multiplier'] is not None),
                            'conditional_correctness':cert['pass'],'reasons':cert['reasons'],'group_errors':cert['group_errors'],
                            'max_range_ratio':max(cert['range_ratios_upper'],key=F)})
                    except (ValueError,ArithmeticError) as error:
                        record.update({'conditional_correctness':False,'reasons':[str(error)]})
                    stream.write(json.dumps(record,separators=(',',':'))+'\n')
                    for reason in record['reasons']:counts[reason]=counts.get(reason,0)+1
                    if record['conditional_correctness']:passing.append(record)
        fronts={str(n):pareto([r for r in passing if r['branch']['N']==n]) for n in summary['family']['N']}
        results.append({'method':block['method'],'groups':list(groups),'attempts':len(seen),
                        'conditional_passes':len(passing),'failure_counts':counts,'fronts_by_N':fronts})
    return {'schema':'new-public-one-bit-refinement-v1','question':q,'family':summary['family'],
            'rule':'same +/-3 scale bits around each surviving coarse recipe, rebuild and recertify',
            'results':results,'security_estimated':False,'HE_executions':0}


if __name__=='__main__':
    a=argparse.ArgumentParser();a.add_argument('summary');a.add_argument('out');v=a.parse_args()
    out=Path(v.out);out.mkdir();source=Path(v.summary)
    with gzip.open(out/'all_refined_candidates.jsonl.gz','xt') as log:result=refine(json.loads(source.read_text()),log)
    result['coarse_summary_sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
    result['program_sha256']=hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    with (out/'summary.json').open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    for block in result['results']:
        print(block['method'],block['attempts'],block['conditional_passes'],flush=True)
        for n,rows in block['fronts_by_N'].items():
            if not rows:continue
            chosen=min(rows,key=lambda r:r['resources']['square_Q_words']+r['resources']['ks_transform_word_proxy'])
            c=to_go_config(result['question'],block['method'],[chosen])
            with (out/f"{block['method']}_N{n}_public_config.json").open('x') as f:json.dump(c,f,indent=2);f.write('\n')
