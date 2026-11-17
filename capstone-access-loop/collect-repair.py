from pathlib import Path
import json
import subprocess as sp
import sys
import time

r = Path(__file__).resolve().parent
run_id, = sys.argv[1:]
endpoint = 'repos/gmh5225/test_mac_intel/actions/runs/' + run_id
previous = None
while True:
    run = json.loads(sp.check_output(['gh', 'api', endpoint], text=True))
    receipt = {k: run[k] for k in ('id', 'head_sha', 'status', 'conclusion', 'html_url', 'run_attempt')}
    assert receipt['head_sha'] == (r / 'repair-revision.txt').read_text().strip()
    (r / 'repair-run.json').write_text(json.dumps(receipt, indent=2) + '\n')
    artifacts = json.loads(sp.check_output(['gh', 'api', endpoint + '/artifacts'], text=True))['artifacts']
    for item in artifacts:
        dest = r / 'repair' / item['name']
        if not (dest / 'download.json').exists():
            sp.run([sys.executable, r.parent / 'round361-shared-x86-guarded-arm-ppc/evidence.py',
                    run_id, item['name'] + '=' + str(dest)], check=True)
    state = (run['status'], run['conclusion'], len(artifacts))
    if state != previous:
        print(state, flush=True)
        previous = state
    if run['status'] == 'completed':
        assert run['conclusion'] == 'success'
        sp.run([sys.executable, r / 'review-profiles.py'], check=True)
        break
    time.sleep(30)
