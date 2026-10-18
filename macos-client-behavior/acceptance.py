"""Native Mac source-client hooks, MCP and interrupt comparisons."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import traceback

ROOT = Path(__file__).resolve().parent
REPO = ROOT.parent
sys.dont_write_bytecode = True
sys.path.insert(0, str(REPO / 'macos-native-components'))
from client_acceptance import Harness, sha, write, initialize
from client_protocol import run as protocol
from client_build import build
from client_ci import published_input
from source_engine import qualify as qualify_engine
from behavior_oracles import check_case
sys.path.insert(0, str(REPO / 'musl-native-components'))
from private_diagnostics import seal

SID = '00000000-0000-4000-8000-000000000001'
UID = '00000000-0000-4000-8000-000000000011'
HEADER_URL = 'https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp'
HEADER_SHA256 = '9bea4c8066ef4a1c206b2be5a36302f8926f7fdc6087af5d20b417d0cf103ea6'
GROUPS = ['H01', 'H02', 'H03', 'M01', 'M02', 'T03']


def encryption(private, public):
    previous = os.environ.get('PATH', '')
    candidates = [Path('/opt/homebrew/opt/openssl@3/bin'), Path('/usr/local/opt/openssl@3/bin')]
    candidates = [p for p in candidates if (p / 'openssl').is_file()]
    assert candidates, 'OpenSSL 3 is required before any captured client is read'
    try:
        os.environ['PATH'] = str(candidates[0]) + os.pathsep + previous
        return seal(private.resolve(), public.resolve())
    finally:
        os.environ['PATH'] = previous


class BehaviorHarness(Harness):
    def __init__(self, *args, helper, **kwargs):
        self.helper = helper
        super().__init__(*args, **kwargs)

    def profile(self, stage, target, port, capability=None):
        text = super().profile(stage, target, port, capability)
        text += '(allow file-read* file-map-executable process-exec (literal ' + json.dumps(str(self.helper)) + '))\n'
        text += '(allow file-read* file-write* (subpath ' + json.dumps(str(stage / 'helper-log')) + '))\n'
        return text

    def observe(self, result, **kwargs):
        normalized = super().observe(result, **kwargs)
        target = self.logs / result['private'].name
        for name in ['profile.sb', 'qualified-before-client.json']:
            shutil.copyfile(result['private'] / name, target / name)
        shutil.copyfile(result['private'] / 'client/execution.json', target / 'native-execution.json')
        for name in ['boundary.result.json', 'boundary.stdout', 'boundary.stderr']:
            shutil.copyfile(result['private'] / 'control' / name, target / name)
        return normalized

    def qualify_helper(self):
        parent = self.inputs / 'helper-parent.mjs'
        result = subprocess.run([self.helper, '--write-parent-fixture', parent], capture_output=True, timeout=10)
        assert result.returncode == 0 and not result.stdout and not result.stderr
        owned = self.execute('owned-inherited-helper', 'authored', [], setup=lambda stage, argv:
            [str(parent), str(self.helper), str(stage / 'outside-canary')])
        assert owned['frames'] == [dict(code=0, child=dict(denied_file_errno=1, external_connect_errno=1, other_exec_errno=1))]
        self.observe(owned)
        stage = self.output / 'owned-helper-stdio'
        stage.mkdir()
        for part in ['work', 'home', 'tmp', 'fixtures', 'report', 'helper-log']:
            (stage / part).mkdir()
        policy = stage / 'profile.sb'; policy.write_text(self.profile(stage, self.helper, None))
        environment = dict(HOME=str(stage / 'home'), TMPDIR=str(stage / 'tmp'), PATH='/unavailable')
        rows = []

        def run(name, argv, steps, code=0):
            record, stdout, stderr = protocol(['/usr/bin/sandbox-exec', '-f', policy, self.helper, *argv],
                stage / 'work', environment, self.private / ('owned-helper-' + name), steps, wall=10)
            assert record['failure'] is None and not record['kill_errors'] and record['exit_code'] == code and not stderr
            assert record['completed_steps'] == len(steps)
            rows.append(dict(case=name, execution=record, stdout_sha256=hashlib.sha256(stdout).hexdigest()))
            return stdout

        hook_input = dict(hook_event_name='PreToolUse', tool_name='Write', tool_input=dict(file_path='/fixture/created.txt', content='fixture-write\n'))
        for mode in ['observe', 'deny', 'invalid-json', 'invalid-schema']:
            log = stage / 'helper-log' / (mode + '.jsonl')
            raw = run('hook-' + mode, ['--hook', mode, '--log', str(log)], [dict(send_json=hook_input), dict(close_stdin=True)])
            assert [json.loads(line) for line in log.read_text().splitlines()] == [hook_input]
            if mode == 'invalid-json':
                assert raw == b'{ invalid\n'
            elif mode == 'observe':
                assert json.loads(raw) == {}
            else:
                assert json.loads(raw)['hookSpecificOutput']['permissionDecision'] == ('deny' if mode == 'deny' else 42)
        steps = [
            dict(send_json=dict(jsonrpc='2.0', id=1, method='initialize', params=dict(protocolVersion='2025-06-18', capabilities={}, clientInfo=dict(name='fixture', version='1')))),
            dict(wait_json={'id': 1}), dict(send_json=dict(jsonrpc='2.0', method='notifications/initialized')),
            dict(send_json=dict(jsonrpc='2.0', id=2, method='tools/list', params={})), dict(wait_json={'id': 2}),
            dict(send_json=dict(jsonrpc='2.0', id=3, method='tools/call', params=dict(name='echo', arguments=dict(text='self-fixture-token')))),
            dict(wait_json={'id': 3}), dict(close_stdin=True)]
        raw = run('MCP-roundtrip', ['--mcp-echo', '--log', str(stage / 'helper-log/mcp.jsonl')], steps)
        frames = [json.loads(line) for line in raw.splitlines()]
        assert len(frames) == 3 and frames[2]['result']['content'][0]['text'] == 'fixture-mcp:self-fixture-token'
        run('MCP-failed-helper', ['--mcp-fail'], [dict(close_stdin=True)], code=2)
        self.receipt['helper_controls'] = dict(status='qualified', helper_sha256=sha(self.helper),
            inherited_external_file_network_and_other_exec_denied=True, cases=rows)

    def accept_behavior(self, groups=None):
        groups = GROUPS if groups is None else groups
        assert groups and set(groups) <= set(GROUPS) and len(set(groups)) == len(groups)
        matrix_file = REPO / 'windows-recovery/behavior-fixtures.json'
        matrix = json.loads(matrix_file.read_bytes())
        write(self.logs / 'behavior-case-matrix.json', matrix)
        count = 0
        for case in matrix['cases']:
            if case['id'] not in groups:
                continue
            variants = case['variants']
            if case['id'] == 'H03':
                variants = [dict(variants[0], id='invalid_text_continue'), dict(variants[0], id='invalid_schema_block')]
            for variant in variants:
                name = case['id'] + '-' + variant['id']; observations = {}
                for label in self.clients:
                    spec = json.loads(json.dumps(variant['stub'])) if 'stub' in variant else None
                    steps = None
                    if case['id'] in ['M02', 'T03']:
                        steps = initialize()
                        if case['id'] == 'M02':
                            # Reconnect acknowledges only after applying the failed
                            # connection state. Querying immediately after generic
                            # initialization races deferred MCP startup.
                            steps += [dict(send_json=dict(type='control_request', request_id='mcp-reconnect-1', request=dict(subtype='mcp_reconnect', serverName='fixture'))),
                                dict(wait_json={'type': 'control_response', 'response.request_id': 'mcp-reconnect-1', 'response.subtype': 'error'}),
                                dict(send_json=dict(type='control_request', request_id='mcp-status-1', request=dict(subtype='mcp_status'))),
                                dict(wait_json={'type': 'control_response', 'response.request_id': 'mcp-status-1'}), dict(close_stdin=True)]
                        else:
                            steps += [dict(send_json=dict(type='user', uuid=UID, session_id=SID, parent_tool_use_id=None, message=dict(role='user', content='fixture prompt'))),
                                dict(wait_json={'type': 'stream_event', 'event.type': 'content_block_delta', 'event.delta.text': 'fixture-start'}),
                                dict(send_json=dict(type='control_request', request_id='interrupt-1', request=dict(subtype='interrupt'))),
                                dict(wait_json={'type': 'result'}), dict(close_stdin=True)]

                    def setup(stage, argv):
                        (stage / 'helper-log').mkdir()
                        substitutions = {'{{R}}': str(stage), '{{H}}': str(stage / 'home'), '{{W}}': str(stage / 'work'),
                            '{{F}}': str(stage / 'fixtures'), '{{SID}}': SID, '{{HELPER}}': str(self.helper)}

                        def replace(value):
                            if isinstance(value, str):
                                for key, text in substitutions.items():
                                    value = value.replace(key, text)
                                return value
                            if isinstance(value, dict):
                                return {k: replace(v) for k, v in value.items()}
                            if isinstance(value, list):
                                return [replace(v) for v in value]
                            return value

                        for key, value in matrix['fixtures'].items():
                            if '{{R}}/sibling/' in key:
                                continue
                            if ('mcp' in key or 'hooks-' in key) and 'HELPER' not in case['capability']:
                                continue
                            file = Path(replace(key)); assert file.is_relative_to(stage)
                            file.parent.mkdir(parents=True, exist_ok=True)
                            rendered = replace(value)
                            if case['id'] == 'H03' and variant['id'] == 'invalid_schema_block' and key == '{{F}}/hooks-fail-closed.json':
                                rendered['hooks']['PreToolUse'][0]['hooks'][0]['args'][1] = 'invalid-schema'
                            file.write_text(rendered if isinstance(rendered, str) else json.dumps(rendered) + '\n')
                        if spec is not None:
                            rendered = replace(spec); spec.clear(); spec.update(rendered)
                        return replace(argv)

                    result = self.execute('behavior-' + name + '-' + label, label, variant['argv'], spec=spec, steps=steps, setup=setup,
                        expected_exit_code=1 if case['id'] == 'T03' else 0)
                    execution = result['execution']; assert not execution['kill_errors']
                    run = dict(timeout=False, protocol_error=None, output_limit_reached=False, exit_code=execution['exit_code'])
                    api = [r for r in result['requests'] if r['path'].split('?')[0] == '/v1/messages']
                    errors = check_case(case, variant, run, result['frames'], api, result['stage'], result['private'], {}, self.output, [])
                    if case['id'] == 'M02':
                        failed = [f for f in result['frames'] if f.get('type') == 'control_response' and f.get('response', {}).get('request_id') == 'mcp-reconnect-1']
                        assert len(failed) == 1 and failed[0]['response']['subtype'] == 'error' and failed[0]['response'].get('error')
                    write(result['private'] / 'behavior-oracle.json', dict(case=name, label=label, errors=errors, execution=execution,
                        created_file_sha256=sha(result['stage'] / 'work/created.txt') if (result['stage'] / 'work/created.txt').exists() else None))
                    assert not errors, name + ' semantic oracle failed'
                    observations[label] = self.observe(result)
                    target = self.logs / result['private'].name
                    for filename in ['behavior-oracle.json', 'hook-records.json', 'mcp-records.json', 'hold.json']:
                        if (result['private'] / filename).is_file():
                            shutil.copyfile(result['private'] / filename, target / filename)
                self.compare(name, observations); count += 1
        expected = len(groups) + int('H03' in groups)
        assert count == expected and len(self.receipt['differential_pairs']) == 2 * expected
        self.receipt['matrix_sha256'] = sha(matrix_file)
        self.receipt['case_groups'] = groups


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--arch', choices=['arm64', 'x64'], required=True)
    for name in ['engine', 'output', 'public-output']:
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--original', type=Path)
    args = parser.parse_args()
    output = args.output.resolve(); public = args.public_output.resolve()
    output.mkdir(mode=0o700); public.mkdir()
    receipt = dict(status='started', arch=args.arch, real_credentials_used=False, captured_source_or_clients_uploaded=False, goal_complete=False)
    harness = None
    try:
        assert platform.system() == 'Darwin' and platform.machine() == {'arm64': 'arm64', 'x64': 'x86_64'}[args.arch] and os.getuid() != 0
        preflight = output / 'own-envelope-control'; preflight.mkdir()
        (preflight / 'private-harness-receipt.json').write_text('{"authored_only":true}\n')
        (public / 'own-envelope-control').mkdir()
        receipt['encryption_preflight'] = encryption(preflight, public / 'own-envelope-control')
        controller_proof = output / 'owned-process-retirement.json'
        tested = subprocess.run([sys.executable, '-B', ROOT / 'test_protocol_retirement.py', '--receipt', controller_proof],
            capture_output=True, timeout=30)
        if tested.returncode != 0:
            evidence = output / 'execution-records'; evidence.mkdir()
            (evidence / 'owned-controller.stdout').write_bytes(tested.stdout)
            (evidence / 'owned-controller.stderr').write_bytes(tested.stderr)
        assert tested.returncode == 0
        control = json.loads(controller_proof.read_bytes())
        assert control['status'] == 'four_native_Darwin_process_retirement_controls_passed' and not control['captured_inputs_executed']
        assert control['protocol_sha256'] == sha(REPO / 'macos-native-components/client_protocol.py')
        assert control['native_architecture'] == platform.machine() and len(control['cases']) == 4
        shutil.copyfile(controller_proof, public / controller_proof.name)
        receipt['native_process_retirement_controls_sha256'] = sha(controller_proof)
        engine = output / 'bun-source-engine'
        subprocess.run(['/bin/cp', '-c', args.engine.resolve(), engine], check=True); engine.chmod(0o500)
        source_engine = qualify_engine(args.arch, engine)
        include = output / 'owned-include/nlohmann'; include.mkdir(parents=True)
        fetched = subprocess.run(['curl', '--http1.1', '--fail', '--silent', '--show-error', '--location',
            '--retry', '3', '--retry-all-errors', '--max-time', '45', '--max-filesize', '1048576',
            '--output', str(include / 'json.hpp'), HEADER_URL], capture_output=True, timeout=210)
        assert fetched.returncode == 0, 'authored header download failed: curl exit ' + str(fetched.returncode)
        assert sha(include / 'json.hpp') == HEADER_SHA256
        helper = output / 'owned-stdio-helper'
        compiler = ['xcrun', 'clang++', '-std=c++20', '-O2', '-Wall', '-Wextra', '-Werror', '-I', include.parent, ROOT / 'offline-stdio-helper.cpp', '-o', helper]
        result = subprocess.run(list(map(str, compiler)), capture_output=True, timeout=120)
        assert result.returncode == 0 and not result.stdout and not result.stderr, 'authored helper compilation failed'
        receipt['authored_helper'] = dict(source_sha256=sha(ROOT / 'offline-stdio-helper.cpp'), binary_sha256=sha(helper),
            header_url=HEADER_URL, header_sha256=HEADER_SHA256)
        original = args.original.resolve() if args.original else published_input(args.arch, output / 'published-input')
        pins = json.loads((REPO / 'macos-native-components/original-pins.json').read_bytes())
        assert original.stat().st_size == pins[args.arch]['bytes'] and sha(original) == pins[args.arch]['sha256']
        built = build(args.arch, original, engine, output / 'private-build', output / 'client-build-logs')
        client_pins = json.loads((REPO / 'macos-native-components/source-client-pins.json').read_bytes())
        assert {k: {field: v[field] for field in ['sha256', 'bytes']} for k, v in built['clients'].items()} == client_pins['profiles'][args.arch]['clients']
        logs = output / 'accepted-records'
        harness = BehaviorHarness(args.arch, original, engine, output / 'client-build-logs/native-client-build.json', output / 'execution-work', logs, helper=helper)
        harness.qualify_fixture(); harness.qualify_helper(); harness.accept_behavior()
        assert all(sha(file) == harness.receipt['client_sha256'][label] for label, file in harness.clients.items())
        assert sha(original) == pins[args.arch]['sha256'] and sha(engine) == source_engine['binary_sha256']
        harness.receipt.update(status='seven_native_Mac_helper_and_interrupt_cases_match_both_source_layouts', input_clients_preserved=True)
        write(logs / 'client-acceptance.json', harness.receipt)
        shutil.copytree(logs, public / 'accepted-records')
        shutil.copyfile(output / 'client-build-logs/native-client-build.json', public / 'source-build.json')
        for layout in ['preserved', 'readable']:
            target = public / ('source-build-' + layout); target.mkdir()
            shutil.copyfile(output / 'private-build' / layout / 'mapping.tsv', target / 'selected-module-hashes.tsv')
            shutil.copyfile(output / 'private-build' / layout / 'readback/mapping.tsv', target / 'readback-module-hashes.tsv')
            shutil.copyfile(output / 'client-build-logs' / (layout + '-signed-layout.json'), target / 'signed-layout.json')
        recipes = public / 'recipes'; recipes.mkdir()
        for file in ROOT.iterdir():
            if file.is_file():
                shutil.copyfile(file, recipes / file.name)
        for name in ['behavior-fixtures.json', 'behavior_oracles.py']:
            shutil.copyfile(REPO / 'windows-recovery' / name, recipes / name)
        shutil.copyfile(REPO / 'macos-native-components/source-client-pins.json', recipes / 'source-client-pins.json')
        receipt.update(status=harness.receipt['status'], native_host=True, runtime_os_version=platform.mac_ver()[0],
            source_engine=source_engine, client_sha256=harness.receipt['client_sha256'], differential_pairs=14,
            build_receipt_sha256=sha(output / 'client-build-logs/native-client-build.json'),
            actual_nested_product_Bash_sandbox_accepted=False, retained_native_addon_functions_invoked=False)
    except Exception as error:
        receipt.update(status='failed_private_diagnostics_only', error_type=type(error).__name__)
        transport_file = output / 'published-input/transport-diagnostic.json'
        write(output / 'private-harness-receipt.json', dict(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc(),
            input_transport=json.loads(transport_file.read_bytes()) if transport_file.is_file() else None, harness=harness.receipt if harness else None))
        if harness is not None:
            shutil.copytree(harness.private, output / 'execution-records', dirs_exist_ok=True)
        try:
            receipt['private_diagnostics'] = encryption(output, public)
        except Exception as encryption_error:
            receipt['private_diagnostic_encryption_error_type'] = type(encryption_error).__name__
        write(public / 'receipt.json', receipt)
        print(json.dumps(dict(status=receipt['status'], error_type=receipt['error_type'], plaintext_exported=False)))
        return 1
    write(public / 'receipt.json', receipt)
    files = [dict(file=f.relative_to(public).as_posix(), bytes=f.stat().st_size, sha256=sha(f)) for f in sorted(public.rglob('*')) if f.is_file()]
    write(public / 'MANIFEST.json', dict(schema_version=1, files=files))
    print(json.dumps(dict(status=receipt['status'], differential_pairs=14, arch=args.arch)))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
