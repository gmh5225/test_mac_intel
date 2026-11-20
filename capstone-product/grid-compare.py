"""Compare actual test outcomes and retained GTest diagnostics from both binaries."""
from collections import Counter
from pathlib import Path
import hashlib
import json
import re
import sys
import xml.etree.ElementTree as ET

def outcomes(path):
    result={}
    for case in ET.parse(path).iter('testcase'):
        name=case.get('name')
        assert name and name not in result
        output=case.findtext('system-out') or case.findtext('failure') or ''
        failed=case.find('failure') is not None or case.find('error') is not None
        skipped=case.find('skipped') is not None or case.get('status')=='notrun' or re.search(r'^\[\s*SKIPPED\s*\] ',output,re.M)
        state='failed' if failed else 'skipped' if skipped else 'passed'
        if failed:
            diagnostic=output[output.find('[ RUN '):]
            diagnostic=re.sub(r'/tmp/neverd_rt_\d+/t\d+/', '/tmp/roundtrip/', diagnostic)
            diagnostic=re.sub(r'\(\d+(?:\.\d+)? ms(?: total)?\)', '(elapsed)',diagnostic)
            result[name]=(state,hashlib.sha256(diagnostic.encode()).hexdigest())
        else:
            result[name]=(state,None)
    assert result
    return result

def summarize(x):
    return dict(Counter(v[0] for v in x.values()))

if __name__=='__main__':
    root=Path(sys.argv[1])
    base,candidate=(outcomes(root/(name+'.xml')) for name in ('baseline','candidate'))
    assert len(base)>15000 and set(base)==set(candidate)
    for label in ('baseline','candidate'):
        decode=outcomes(root/(label+'-decoder.xml'))
        assert len(decode)>=43 and all(v[0]=='passed' for v in decode.values()),(label,summarize(decode))
    changed=[(k,base[k],candidate[k]) for k in base if base[k][0]!=candidate[k][0]]
    different=[k for k in base if base[k][0]==candidate[k][0]=='failed' and base[k][1]!=candidate[k][1]]
    data=dict(complete=True,baseline=summarize(base),candidate=summarize(candidate),tests=len(base),
              new_failures=[k for k,a,b in changed if b[0]=='failed'],
              changed_outcomes=changed,changed_failure_diagnostics=different,
              shared_failures=[k for k in base if base[k][0]==candidate[k][0]=='failed'],
              source=json.loads((root/'inputs.json').read_text()),llvm=(root/'llvm.txt').read_text().strip(),
              decoder_tests_per_build=len(decode))
    (root/'paired-review.json').write_text(json.dumps(data,indent=2)+'\n')
    print(data['baseline'],data['candidate'],len(changed),len(different),flush=True)
    assert not changed and not different
