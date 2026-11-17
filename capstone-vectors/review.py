from collections import Counter
from pathlib import Path
import json

r = Path(__file__).resolve().parent
read = lambda p: json.loads(p.read_text())
run, protocol = read(r / 'run.json'), read(r / 'protocol.json')
assert run['conclusion'] == 'success' and run['head_sha'] == (r / 'revision.txt').read_text().strip()
d, = (r / 'results').iterdir()
assert read(d / 'download.json')['digest'].startswith('sha256:')
assert read(d / 'cleanup.json')['removed']
done = read(d / 'complete.json')
assert done['success'] and done['panels'] == 7 and not done['timing'] and done['protocol'] == protocol
assert read(d / 'existingmiss-tested-source.json')['tree'] == protocol['source']['tree']
panels = read(d / 'census.json')
assert len(panels) == 7
summaries = []
for panel in panels:
    assert panel['invalid_bytes'] == 0
    assert panel['decoded'] == sum(row['count'] for row in panel['rows'])
    remaining = Counter()
    for row in panel['rows']:
        if row['route'] == 'miss':
            remaining[(row['mnemonic'], row['family'], row['memory'], row['w'], row['ll'], row['pp'], row['evex_flags'])] += row['count']
    summaries.append(dict(case=panel['case'], panel=panel['panel'], decoded=panel['decoded'],
                          existing=panel['existing'], new=panel['new'], miss=panel['miss'],
                          largest_remaining=[dict(mnemonic=k[0],family=k[1],memory=k[2],w=k[3],ll=k[4],pp=k[5],evex_flags=k[6],count=v) for k,v in remaining.most_common(25)]))
ssl, = [x for x in panels if x['case'] == 'libssl3t64-amd64']
assert ssl['decoded'] == 187130 and ssl['new'] == 7425
result = dict(complete=True, run=run, protocol=protocol, summaries=summaries, raw=str(d.relative_to(r)),
              cleanup=read(d / 'cleanup.json'), scope='Static corpus admission counts on frozen common instruction boundaries. This is not a native speed measurement or application runtime-frequency sample.')
(r / 'review.json').write_text(json.dumps(result, indent=2) + '\n')
for row in summaries:
    print(row['case'],row['panel'],'new',row['new'],'remaining',row['miss'],row['largest_remaining'][:4])
