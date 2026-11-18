from pathlib import Path
import json
import subprocess as sp
import sys
import time

r = Path(__file__).resolve().parent
run_id, = sys.argv[1:]
endpoint = 'repos/gmh5225/test_mac_intel/actions/'
last = None
def api(path):
    for attempt in range(3):
        try:
            return json.loads(sp.check_output(['gh', 'api', endpoint + path], text=True))
        except sp.CalledProcessError:
            if attempt == 2:
                raise
            print('Retrying read-only Actions API request after failure:', path, flush=True)
            time.sleep(10)

while True:
    run = api('runs/' + run_id)
    receipt = {key: run[key] for key in ('id', 'head_sha', 'status', 'conclusion', 'html_url', 'run_attempt')}
    (r / 'profile-run.json').write_text(json.dumps(receipt, indent=2) + '\n')
    artifacts = api('runs/' + run_id + '/artifacts')['artifacts']
    missing = []
    for item in artifacts:
        dest = r / 'profile' / item['name']
        expected = {key: item[key] for key in ('id', 'name', 'digest', 'size_in_bytes')}
        if not (dest / 'download.json').exists() or json.loads((dest / 'download.json').read_text()) != expected:
            missing.append(item['name'] + '=' + str(dest))
    if missing:
        sp.run([sys.executable, r.parent / 'round361-shared-x86-guarded-arm-ppc/evidence.py', run_id, *missing], check=True)
    state = (run['status'], run['conclusion'], len(artifacts))
    if state != last:
        print(state, flush=True)
        last = state
    if run['status'] == 'completed':
        assert run['conclusion'] == 'success', receipt
        sp.run([sys.executable, r / 'review.py'], check=True)
        break
    time.sleep(30)
