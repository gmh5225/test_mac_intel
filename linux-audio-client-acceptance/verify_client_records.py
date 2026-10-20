"""Recompute admitted full-client pairs from raw streams, API and files."""
from pathlib import Path
import argparse
import hashlib
import json
import sys


def load(path):
    return json.loads(path.read_bytes())


def verify(receipt_path, recipes):
    sys.path.insert(0, str(recipes / 'seccomp-helper'))
    from compare_bash import Normalize
    from bash_tool_cases import cases as bash_cases
    matrix_path = recipes / 'windows-recovery/search-tool-cases.json'
    assert hashlib.sha256(matrix_path.read_bytes()).hexdigest() == '34e694c01daae7d1fbc9f053c96b48e588d07c381ee514ae49b02907e981fa7e'
    matrix = load(matrix_path); assert len(matrix) == 13
    receipt = load(receipt_path); logs = receipt_path.parent / 'execution-records'
    assert receipt['full_client_runtime_accepted'] and receipt['differential_pairs'] == 40
    assert receipt['Bash_pairs'] == 14 and receipt['Grep_Glob_pairs'] == 26
    assert receipt['actual_Bash_sandbox_enabled'] and not receipt['normalizers_modified']

    def observation(folder, text, tools, errors, contains, excludes):
        process = load(folder / 'process.json')
        assert process['exit_code'] == 0 and process['stderr'] == ''
        frames = [json.loads(line) for line in process['stdout'].splitlines()]
        terminal = [f for f in frames if f.get('type') == 'result']
        assert len(terminal) == 1 and terminal[0]['result'] == text and not terminal[0]['is_error']
        requests = [json.loads(line) for line in (folder / 'requests.jsonl').read_text().splitlines()]
        api = [r for r in requests if r['path'].split('?')[0] == '/v1/messages']
        assert len(api) == len(tools) + 1
        results = []
        for ordinal, error in enumerate(errors, 1):
            matches = [c for m in api[ordinal]['body']['messages'] if isinstance(m.get('content'), list)
                       for c in m['content'] if c.get('type') == 'tool_result' and
                       c.get('tool_use_id') == 'toolu_offline_fixture_' + str(ordinal)]
            assert len(matches) == 1 and bool(matches[0].get('is_error', False)) == error
            results.append(matches[0])
        content = json.dumps(results[-1]['content'], ensure_ascii=False)
        assert all(s in content.replace('\\"', '"') for s in contains)
        assert all(s not in content for s in excludes)
        value = Normalize('/home/test').value(dict(protocol=frames, requests=[r['body'] for r in requests],
                                                 stderr=process['stderr'], exit=process['exit_code']))
        assert value == load(folder / 'normalized.json')
        return value, load(folder / 'workspace-files.json')

    for label in ['original', 'client-preserved', 'client-readable']:
        result = load(logs / ('version-' + label) / 'process.json')
        assert result == dict(exit_code=0, stdout='2.1.296 (Claude Code)\n', stderr='')
    count = 0
    for case in bash_cases():
        values = []
        for label in ['original', 'preserved', 'readable']:
            value, files = observation(logs / ('bash-' + label + '-' + case['id']),
                                       'bash-sandbox-complete', [{}], [case['error']], case['contains'], [])
            assert files == {k: v.encode().hex() for k, v in case['files'].items()}
            values.append(value)
        assert values[0] == values[1] == values[2]
        count += 2
    for case in matrix:
        values = []
        for label in ['original', 'preserved', 'readable']:
            value, files = observation(logs / ('native-search-' + label + '-' + case['id']),
                                       'core-tools-complete', case['tools'], case['tool_errors'],
                                       case['last_result_contains'], case['last_result_excludes'])
            assert files == {'input.txt': case['expected'].encode().hex()}
            values.append(value)
        assert values[0] == values[1] == values[2]
        count += 2
    assert count == 40
    last = receipt['process_budget_observations'][-1]['after']
    assert last['pids.events'] == 'max 0' and last['pids.current'] == '2'
    assert 'oom_kill 0' in last['memory.events']
    return dict(status='raw_40_pairs_and_3_versions_recomputed', pairs=count, arch=receipt['arch'],
                raw_protocol_and_requests=True, exact_workspace_bytes=True,
                receipt_sha256=hashlib.sha256(receipt_path.read_bytes()).hexdigest())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--receipt', type=Path, required=True)
    parser.add_argument('--recipes', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.receipt.resolve(), args.recipes.resolve())
    with args.output.open('x') as stream:
        stream.write(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
