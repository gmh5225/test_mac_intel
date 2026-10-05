"""Read-only replay of the full independent API evidence audit.

Original archive bytes are required; runtime source pins remain immutable.
"""
import ast
from functools import partial
import datetime
import hashlib
import types
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile
from unittest.mock import patch

HARNESS = Path(__file__).resolve().parents[1]
BASE = HARNESS / 'results/2026-10-05-api-lifecycle'
WORKFLOW = 'd61a4910cf6a05041786c979ef570ac29a054636'
ORIGINAL = WORKFLOW
FINAL_ONLY = '4e4350ee23348c4fe9e0902ff8fb1791570086c6'
ENTRY_TIMING = 'ac717e4288a5ff1e6ce7c93d73568e2739b9c58b'
EXECUTION_ACCOUNTING = 'fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b'
EXPLICIT_EXIT = 'ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12'
HELPER = '4e80b1394cfb2489fde177b30167629db71e693d'
contract = native_audit = None


def sha(data):
    return hashlib.sha256(data).hexdigest()


def source(name):
    return subprocess.check_output(['git', '-C', str(HARNESS), 'show', WORKFLOW + ':' + name], timeout=10)


def source_names():
    module = ast.parse(source('scripts/intel_api_lifecycle.py'))
    assignment, = [statement for statement in module.body if isinstance(statement, ast.Assign)
                   and any(isinstance(target, ast.Name) and target.id == 'SOURCES' for target in statement.targets)]
    return ast.literal_eval(assignment.value)


def load_reviewed_contract():
    """Load only a reviewed immutable Git object; never execute artifact code."""
    module = types.ModuleType('reviewed_contract_' + WORKFLOW)
    exec(compile(source('scripts/intel_api_contract.py'),
                 WORKFLOW + ':intel_api_contract.py', 'exec'), module.__dict__)
    return module


def verify_server_identity(snapshot, manifest, run_id):
    run = snapshot['run']
    repository = 'gmh5225/test_mac_intel'
    api = 'https://api.github.com/repos/' + repository
    require(str(run['id']) == run_id and run['head_sha'] == WORKFLOW, 'run/source identity')
    require(type(run['run_attempt']) is int and run['run_attempt'] > 0, 'run attempt')
    require(run['event'] == 'workflow_dispatch' and run['path'] == '.github/workflows/intel-api-lifecycle.yml'
            and run['workflow_id'] == 375021775 and run['head_branch'] == 'main', 'workflow')
    for key in ('repository', 'head_repository'):
        require(run[key]['id'] == 1403853184 and run[key]['full_name'] == repository, 'repository')
    for key, suffix in [('url', ''), ('jobs_url', '/jobs'), ('artifacts_url', '/artifacts')]:
        require(run[key] == api + '/actions/runs/' + run_id + suffix, 'run URL')
    require(run['html_url'] == 'https://github.com/' + repository + '/actions/runs/' + run_id, 'run page')
    observation = '' if WORKFLOW == ORIGINAL else 'final-only / '
    guest_prefix='halt / ' if WORKFLOW==EXPLICIT_EXIT else ''
    match = re.fullmatch(r'Independent HVF / ' + guest_prefix + r'(vcpu|vm) / ' + observation +
                        r'1000 iterations / (macos-(?:15|26)-intel)', run['display_title'])
    require(match is not None, 'dispatch title')
    if WORKFLOW==EXPLICIT_EXIT:require(match[1]=='vcpu','unreviewed halt lifecycle')
    image = match[2]
    jobs = snapshot['jobs']
    require(jobs['total_count'] == len(jobs['jobs']) == 1, 'job inventory')
    job, = jobs['jobs']
    require(job['run_id'] == run['id'] and job['run_attempt'] == run['run_attempt'] and
            job['head_sha'] == WORKFLOW and job['head_branch'] == run['head_branch'], 'job provenance')
    require(job['labels'] == [image] and job['name'] == 'control', 'job image')
    require(job['run_url'] == run['url'] and job['url'] == api + '/actions/jobs/' + str(job['id']), 'job URL')
    require(job['html_url'] == run['html_url'] + '/job/' + str(job['id']), 'job page')
    if run['status'] == 'completed':
        require(job['status'] == 'completed' and job['conclusion'] == run['conclusion'], 'terminal job')
    server = snapshot['artifacts']
    require(len(manifest) == server['total_count'] == len(server['artifacts']), 'artifact count')
    require(len({a['id'] for a in manifest}) == len(manifest), 'duplicate local artifact')
    require(len({a['id'] for a in server['artifacts']}) == len(manifest), 'duplicate server artifact')
    require({a['id']: (a['name'], a['digest']) for a in manifest} ==
            {a['id']: (a['name'], a['digest']) for a in server['artifacts']}, 'server artifact inventory')
    for artifact in server['artifacts']:
        require(artifact['workflow_run'] == {'id': run['id'], 'repository_id': 1403853184,
                'head_repository_id': 1403853184, 'head_branch': 'main', 'head_sha': WORKFLOW}, 'artifact provenance')
        require(artifact['url'] == api + '/actions/artifacts/' + str(artifact['id']) and
                artifact['archive_download_url'] == artifact['url'] + '/zip', 'artifact URL')


def require(value, message):
    if not value:
        raise ValueError(message)


def zero(value):
    return type(value) is int and value == 0


def stamp(text):
    return datetime.datetime.fromisoformat(re.sub(r'\s+(?=[+-][0-9]{4}$)', '', text).replace('Z', '+00:00'))


def crash_time_matches(report, upload):
    captured = stamp(report['captureTime'])
    return stamp(upload['started_at']) - datetime.timedelta(seconds=1) <= captured <= \
           stamp(upload['completed_at']) + datetime.timedelta(seconds=30)


def successful_process(record):
    return (zero(record['exit_status']) and record['signal'] is None
            and record['termination_reason'] is None and record['spawn_error'] is None
            and stamp(record['completed_at']) >= stamp(record['started_at']))


def audit_prefix(raw, mode):
    """Stop the unchanged event contract at EOF; never synthesize final records."""
    terminated = raw[:raw.rfind(b'\n') + 1]
    if not terminated:
        return {'complete_iterations': 0, 'verified_events': 0,
                'unverified_trailing_bytes': len(raw), 'native_exit_verified': False}
    class EndOfPrefix(Exception):
        pass
    readers = []
    class PrefixReader(contract.Reader):
        def __init__(self, values):
            super().__init__(values)
            self.completed = 0
            readers.append(self)
        def take(self, kind, **expected):
            if self.index == len(self.values):
                raise EndOfPrefix()
            value = super().take(kind, **expected)
            if kind == 'iteration_complete':
                self.completed += 1
            return value
    with patch.object(contract, 'Reader', PrefixReader):
        try:
            native_audit(terminated, mode)
        except EndOfPrefix:
            pass
    reader, = readers
    return {'complete_iterations': reader.completed, 'verified_events': reader.index,
            'unverified_trailing_bytes': len(raw) - len(terminated), 'native_exit_verified': False}


def check_plan(plan, prepared, run):
    if WORKFLOW!=EXPLICIT_EXIT:
        require('guest' not in plan and 'target_exit' not in plan,'legacy guest relabelled')
    if WORKFLOW in (ORIGINAL,FINAL_ONLY):
        require('event_version' not in plan,'legacy version relabelled')
    expected = {'kind': 'independent-real-mode-finite-control', 'complete_native_acceptance': False,
        'workflow_commit': WORKFLOW, 'source_commit': WORKFLOW, 'helper_commit': HELPER,
        'run_id': str(run['id']), 'run_attempt': str(run['run_attempt']),
        'workflow_repository': 'gmh5225/test_mac_intel', 'iterations': 1000,
        'timeout_seconds': 600, 'guest_hex': 'a30002f4' if WORKFLOW==EXPLICIT_EXIT else 'a30002ebfe', 'slice_ns': 5000000,
        'budget_ns': 2000000000, 'call_limit': 4096, 'event_limit': 65536,
        'max_output_bytes': 32*1024*1024, 'cpu_generations': 1000}
    for key, value in expected.items():
        require(type(plan[key]) is type(value) and plan[key] == value, 'plan mismatch: ' + key)
    require(plan['mode'] in ('vcpu', 'vm'), 'invalid mode')
    require(plan['vm_generations'] == (1 if plan['mode'] == 'vcpu' else 1000), 'VM generation plan')
    require(plan['runner_image'] in ('macos-15-intel', 'macos-26-intel'), 'image')
    if WORKFLOW in (FINAL_ONLY, ENTRY_TIMING, EXECUTION_ACCOUNTING, EXPLICIT_EXIT):
        require(plan['observation'] == 'final-only', 'sealed observation mode')
    else:
        require('observation' not in plan, 'unexpected legacy observation mode')
    if WORKFLOW in (ENTRY_TIMING, EXECUTION_ACCOUNTING, EXPLICIT_EXIT):
        version=4 if WORKFLOW==EXPLICIT_EXIT else 3 if WORKFLOW==EXECUTION_ACCOUNTING else 2
        require(type(plan['event_version']) is int and plan['event_version'] == version, 'native event version')
        require(plan['stdout_transport'] == 'bounded PTY collector with OPOST disabled', 'sealed raw transport')
    if WORKFLOW in (EXECUTION_ACCOUNTING, EXPLICIT_EXIT):
        require(plan['accounting']==['hv_vcpu_get_exec_time','CLOCK_THREAD_CPUTIME_ID',
            'Mach-bracketed cumulative nanoseconds; not physical guest CPU time'], 'accounting methods')
        require(plan['accounting_units']=={'intel_hv_exec':'nanoseconds per Intel hv.h',
            'thread_cpu':'nanoseconds','sample_brackets':'Mach absolute ticks'}, 'accounting units')
    observation = '' if WORKFLOW == ORIGINAL else 'final-only / '
    guest_prefix='halt / ' if WORKFLOW==EXPLICIT_EXIT else ''
    if WORKFLOW==EXPLICIT_EXIT:
        require(plan['mode']=='vcpu' and plan['guest']=='halt' and
                type(plan['target_exit']) is int and plan['target_exit']==12, 'halt plan')
    require(run['display_title'] == f"Independent HVF / {guest_prefix}{plan['mode']} / {observation}1000 iterations / {plan['runner_image']}", 'dispatch')
    command=[plan['binary'], plan['mode'], '1000']+(['halt'] if WORKFLOW==EXPLICIT_EXIT else [])
    require(plan['command'] == command, 'native command')
    require(plan['binary'].endswith('/evidence-bin/hvf-intel-real-mode'), 'binary path')
    require(plan['source'].endswith('/harness'), 'source path')
    require(re.fullmatch('[0-9a-f]{64}', plan['binary_sha256']), 'signed binary digest')
    require(plan['source_hashes'] == {name: sha(source(name)) for name in source_names()}, 'source hashes')
    require(prepared['HVFDOS-LICENSE.txt'] == source('native/HVFDOS-LICENSE.txt'), 'license')
    observations = plan['host_observations']
    require(len(observations) == 7, 'missing host/compiler observations')
    for index in (0, 1, 2, 3, 4, 6):
        require(zero(observations[index]['status']), 'failed mandatory host observation')
    require('x86_64' in observations[1]['stdout'] and 'x86_64' in observations[6]['stdout'], 'host/binary ISA')
    runtime = json.loads(prepared['observer-runtime.json'])
    require(runtime['kind'] == 'actual-hvf-observer-runtime', 'runtime kind')
    require(runtime['host_system'] == 'darwin' and runtime['host_architecture'] == 'x64', 'observer ISA')
    require(re.fullmatch('[0-9a-f]{64}', runtime['node_sha256']), 'observer digest')
    require(re.fullmatch('[0-9a-f-]{36}', runtime['node_native_uuid']), 'observer UUID')
    require(type(runtime['node_bytes']) is int and runtime['node_bytes'] > 0, 'observer length')
    uploader = json.loads(prepared['uploader-runtime.json'])
    require(uploader['runtime'] == runtime and uploader['mode'] == 'default', 'uploader runtime')
    require(uploader['node_options_present'] is False and uploader['parent_exec_argv'] == [], 'uploader options')
    require(uploader['executable'] == runtime['node_executable'], 'uploader executable')
    require(len(uploader['arguments']) == 1 and uploader['arguments'][0].endswith('/artifact-uploader/dist/upload/index.js'), 'uploader args')
    require(uploader['scope'] == 'independent-api-plan-and-progress-children', 'uploader scope')
    return runtime, uploader


def verify_final_only_evidence(observation, archives, final):
    if observation != 'final-only':
        return
    require(not any('-progress-' in name for name in archives), 'final-only progress artifact')
    if final:
        require(not any(name.startswith(('progress-', 'uploads/progress-')) for name in final), 'final-only live observation file')


def verify_check_annotations(snapshot, envelope, annotations):
    """Bind server failure messages to this exact run, job and check suite."""
    run=snapshot['run']
    require(envelope['kind']=='GitHub-job-check-annotations' and
            envelope['run_id']==str(run['id']) and
            envelope['run_attempt']==run['run_attempt'] and
            envelope['head_sha']==run['head_sha'], 'annotation run identity')
    jobs=snapshot['jobs']['jobs']
    require(len(envelope['checks'])==len(jobs), 'annotation check inventory')
    combined=[]
    for entry,job in zip(envelope['checks'],jobs):
        endpoint='https://api.github.com/repos/gmh5225/test_mac_intel/check-runs/'+str(job['id'])
        check=entry['check_run']
        require(entry['job_id']==job['id'] and entry['endpoint']==job['check_run_url']==endpoint,
                'annotation endpoint identity')
        require(check['id']==job['id'] and check['url']==endpoint and
                check['html_url']==job['html_url'] and check['head_sha']==run['head_sha'] and
                check['check_suite']['id']==run['check_suite_id'] and
                check['name']==job['name'], 'annotation check identity')
        require(check['status']==job['status']=='completed' and
                check['conclusion']==job['conclusion']==run['conclusion'], 'annotation terminal status')
        require(check['output']['annotations_url']==endpoint+'/annotations' and
                type(check['output']['annotations_count']) is int and
                check['output']['annotations_count']==len(entry['annotations']), 'annotation inventory')
        combined.extend(entry['annotations'])
    require(combined==annotations, 'flattened annotations differ from bound checks')
    return combined


def audit_run(run_id):
    global WORKFLOW, contract, native_audit
    directory = BASE / run_id
    manifest_file = directory / 'artifacts.json'
    snapshot = json.loads((directory / 'github-status.json').read_text())
    run = snapshot['run']
    require(run['head_sha'] in (ORIGINAL, FINAL_ONLY, ENTRY_TIMING, EXECUTION_ACCOUNTING, EXPLICIT_EXIT), 'unreviewed workflow pin')
    WORKFLOW = run['head_sha']
    contract = load_reviewed_contract()
    native_audit = contract.audit
    manifest = json.loads(manifest_file.read_text())
    verify_server_identity(snapshot, manifest, run_id)
    prefix_name = f"intel-api-attempt-{run['run_attempt']}-"
    archives = {}
    for artifact in manifest:
        require(artifact['name'].startswith(prefix_name), 'wrong run attempt')
        blob = (BASE / 'archives' / f"{artifact['id']}.zip").read_bytes()
        require(artifact['digest'] == 'sha256:' + sha(blob), 'archive digest')
        require(artifact['name'] not in archives, 'duplicate artifact name')
        with zipfile.ZipFile(BASE / 'archives' / f"{artifact['id']}.zip") as archive:
            names = archive.namelist()
            require(len(names) == len(set(names)), 'duplicate archive member')
            require(names == artifact['files'], 'archive member inventory')
            archives[artifact['name']] = {name: archive.read(name) for name in names}
    result = {'kind': 'independent-api-evidence-reconciliation', 'run_id': run_id,
        'workflow_status': run['status'], 'workflow_conclusion': run['conclusion'],
        'workflow_commit': WORKFLOW, 'helper_commit': HELPER, 'artifact_manifest': manifest_file.name,
        'verified_artifacts': len(manifest), 'complete_native_acceptance': False,
        'native_passed': None, 'child_retired': None, 'mode': None,
        'scope': 'isolated authored real-mode control; not NeverD recovery, CPU or Darwin acceptance'}
    prepared = archives.get(prefix_name + 'plan')
    final = archives.get(prefix_name + 'final')
    plan = runtime = uploader = None
    if prepared:
        plan = json.loads(prepared['plan.json'])
        runtime, uploader = check_plan(plan, prepared, run)
        if WORKFLOW==EXPLICIT_EXIT:native_audit=partial(contract.audit,guest=plan['guest'])
        result.update(plan=plan, mode=plan['mode'], image=plan['runner_image'],
                      observer_runtime=runtime, uploader_runtime=uploader)
        verify_final_only_evidence(plan.get('observation', 'live'), archives, final)
        if final:
            for name in ('plan.json', 'observer-runtime.json', 'uploader-runtime.json', 'host-start.json'):
                require(final[name] == prepared[name], 'sealed prepared evidence changed')
    progress = sorted((name, files) for name, files in archives.items() if '-progress-' in name)
    require(len(progress) <= 64, 'progress budget')
    prefix = b''
    windows = []
    previous_size = 0
    pids = set()
    for sequence, (name, files) in enumerate(progress):
        require(name == prefix_name + f'progress-{sequence:03}', 'missing progress sequence')
        require(set(files) == {'output-tail.log', 'metadata.json', 'children.json'}, 'progress files')
        metadata = json.loads(files['metadata.json'])
        require(metadata['workflow_commit'] == WORKFLOW and metadata['helper_commit'] == HELPER, 'progress provenance')
        require(metadata['kind'] == 'independent-real-mode-partial-progress' and
                metadata['complete_native_acceptance'] is False and metadata['sequence'] == sequence, 'progress scope')
        require(metadata['execution_running_at_seal'] is True and metadata['cancelled'] is False, 'progress execution')
        info, raw = metadata['output'], files['output-tail.log']
        require(info['copied_bytes'] == len(raw) and len(raw) <= 8*1024*1024, 'window length')
        require(previous_size <= info['size_at_open'] <= 32*1024*1024, 'window size')
        require(info['first_byte'] == max(0, info['size_at_open'] - 8*1024*1024), 'window offset')
        require(info['truncated'] is (info['first_byte'] != 0), 'window truncation')
        require(info['first_byte'] + len(raw) <= info['size_at_open'], 'window extent')
        previous_size = info['size_at_open']
        prefix = extend(prefix, info['first_byte'], raw)
        lines = raw.split(b'\n')
        if info['first_byte']:
            lines = lines[1:]
        lines = lines[:-1]
        events = [json.loads(line) for line in lines]
        counts = {kind: max([event['iteration'] for event in events if event['event'] == kind] or [0])
                  for kind in ('iteration_begin', 'iteration_complete')}
        require(metadata['progress'] == {'last_completed_in_window': counts['iteration_complete'],
                'last_started_in_window': counts['iteration_begin']}, 'partial counter')
        identity = metadata['identity']
        pid = identity['native_pid']
        require(type(pid) is int and pid > 1, 'progress PID')
        require(json.loads(files['children.json'])['process_groups'] == [pid], 'progress registry')
        pids.add(pid)
        if identity['verified']:
            fields = identity['stdout'].strip().split(None, 3)
            require(zero(identity['status']) and len(fields) == 4 and fields[:3] ==
                    [str(pid), str(identity['python_pid']), str(pid)] and fields[3] == plan['binary'], 'ps identity')
        windows.append({'artifact': name, 'first_byte': info['first_byte'], 'bytes': len(raw),
                        'sha256': sha(raw), 'metadata': metadata})
    require(len(pids) <= 1, 'native identity changed')
    if progress:
        result['partial_progress'] = {'contiguous_bytes': len(prefix), 'sha256': sha(prefix),
            'identical_overlaps': True, 'snapshots': windows,
            'native_exit_verified': False, 'last_observed': windows[-1]['metadata']['progress']}
    if final and 'native-status.json' in final:
        require(plan is not None, 'missing pre-execution plan')
        native = json.loads(final['native-status.json'])
        declared = json.loads(final['result.json']) if 'result.json' in final else None
        retirement = json.loads(final['retirement.json'])
        controller = json.loads(final['controller-status.json'])
        raw = final['output.log']
        require(raw.startswith(prefix), 'final and snapshots disagree')
        require(sha(raw) == native['output_sha256'], 'native digest')
        if declared:
            require(sha(raw) == declared['output_sha256'], 'result digest')
        require(native['command'] == plan['command'], 'actual native command')
        if WORKFLOW in (ENTRY_TIMING, EXECUTION_ACCOUNTING, EXPLICIT_EXIT):
            require(native['pty_output_processing'] is False, 'native OPOST readback')
        require(type(native['pid']) is int and native['pid'] > 1, 'native PID')
        require(not pids or pids == {native['pid']}, 'final native PID')
        require(json.loads(final['children.json'])['process_groups'] == [native['pid']], 'native registry')
        require(retirement == [{'pid': native['pid'], 'status': native['status'], 'retired': native['child_retired']}], 'retirement')
        audited = error = None
        try:
            audited = native_audit(raw, plan['mode'])
        except ValueError as failure:
            error = str(failure)
        passed = None
        if declared:
            require(declared['audit'] == audited and declared['audit_error'] == error, 'independent event audit')
            passed = result_passed(native, audited, error)
            require(declared['passed'] is passed and declared['complete_native_acceptance'] is False, 'declared result')
        uploads = {name.removeprefix('uploads/').removesuffix('.json'): json.loads(value)
                   for name, value in final.items() if re.fullmatch(r'uploads/(?:plan|progress-\d{3})\.json', name)}
        require('plan' in uploads, 'missing plan upload retirement')
        for name, record in uploads.items():
            require(record['executable'] == uploader['executable'] and record['arguments'] == uploader['arguments'], 'actual uploader invocation')
        require(successful_process(uploads['plan']), 'failed pre-execution upload')
        require(stamp(uploads['plan']['completed_at']) <= stamp(controller['started_at']), 'guest before plan upload')
        if passed:
            require(native['elapsed_seconds'] <= 600 and successful_process(controller), 'native/controller budget or exit')
            require(all(successful_process(record) for record in uploads.values()), 'observer failure')
            require(set(uploads) == {'plan', *(name.removeprefix(prefix_name) for name, _ in progress)}, 'upload reconciliation')
            final_step, = [step for job in snapshot['jobs']['jobs'] for step in job['steps']
                           if step['name'] == 'Preserve final or incomplete independent evidence']
            require(stamp(final_step['started_at']) + datetime.timedelta(seconds=1) >=
                    stamp(controller['completed_at']), 'final artifact before controller completion')
        matched_crashes = []
        failed_uploads = {name: record for name, record in uploads.items() if not successful_process(record)}
        if 'uploads/crashes/collection.json' in final:
            collection = json.loads(final['uploads/crashes/collection.json'])
            for capture in collection['captured']:
                upload = failed_uploads[capture['upload']]
                report_name = 'uploads/crashes/' + capture['report']
                header_text, body_text = final[report_name].decode().split('\n', 1)
                header, body = json.loads(header_text), json.loads(body_text)
                require(capture['pid'] == body['pid'] == upload['pid'], 'crash PID')
                require(body['parentPid'] == upload['parent_pid'], 'crash parent')
                require(crash_time_matches(body, upload), 'crash capture time')
                require(body['exception']['signal'] == upload['signal'] == 'SIGSEGV', 'crash signal')
                require(header['slice_uuid'] == runtime['node_native_uuid'], 'crash UUID')
                images = body['usedImages']
                require(any(image.get('uuid') == runtime['node_native_uuid'] and image.get('arch') == 'x86_64'
                            and image.get('name') == 'node' for image in images), 'native runtime image')
                require(Path(body['procPath']).name == 'node' and body['parentProc'] == 'node', 'crash process')
                matched_crashes.append({'upload': capture['upload'], 'pid': body['pid'],
                    'report': report_name, 'report_sha256': sha(final[report_name]),
                    'signal': upload['signal'], 'node_native_uuid': runtime['node_native_uuid'],
                    'exception': body['exception'],
                    'top_frame': body['threads'][body['faultingThread']]['frames'][0]})
        if not declared:
            require(native['controller_interrupted'] is True and native['collection_error'] == 'SystemExit', 'unexplained missing result')
            require(native['status'] == -9 and native['child_retired'] is True, 'interrupted child retirement')
            require(controller['termination_reason'] == 'evidence-failure' and controller['exit_status'] == 143, 'observer cancellation')
            require(failed_uploads, 'missing observer failure')
            result['verified_partial_contract'] = audit_prefix(raw, plan['mode'])
        result.update(native_passed=passed, child_retired=native['child_retired'],
            native_status=native, retirement=retirement, controller=controller,
            native_audit=audited, native_audit_error=error, uploads=uploads,
            output_sha256=sha(raw), output_bytes=len(raw), matched_uploader_crashes=matched_crashes,
            failed_uploads=failed_uploads, final_native_result_present=declared is not None)
    if run['status'] == 'completed' and WORKFLOW==EXPLICIT_EXIT:
        annotations=json.loads((directory/'annotations.json').read_text())
        envelope_bytes=(directory/'check-annotations.json').read_bytes()
        verified=verify_check_annotations(snapshot,json.loads(envelope_bytes),annotations)
        result['runner_loss_explicitly_reported']=any(
            'The hosted runner lost communication with the server' in item['message'] for item in verified)
        result['job_timeout_explicitly_reported']=any(
            item['message']=='The job has exceeded the maximum execution time of 30m0s' for item in verified)
        result['annotations']=verified
        result['check_annotations_sha256']=sha(envelope_bytes)
    elif run['status'] == 'completed' and run['conclusion'] == 'failure':
        annotations = json.loads((directory / 'annotations.json').read_text())
        result['runner_loss_explicitly_reported'] = any('The hosted runner lost communication with the server' in item['message'] for item in annotations)
        result['annotations'] = annotations
    if run['conclusion'] == 'success':
        require(result['native_passed'] is True and result['child_retired'] is True, 'green workflow lacks complete native evidence')
    return result



def extend(prefix, offset, chunk):
    if type(offset) is not int or offset < 0 or offset > len(prefix):
        raise ValueError('missing prefix bytes before snapshot')
    overlap = min(len(prefix) - offset, len(chunk))
    if prefix[offset:offset + overlap] != chunk[:overlap]:
        raise ValueError('immutable snapshots disagree in overlapping bytes')
    return prefix + chunk[overlap:]

def result_passed(status, audited, error):
    return (type(status['status']) is int and status['status'] == 0
            and status['timed_out'] is False and status['child_retired'] is True
            and status['controller_interrupted'] is False and status['collection_error'] is None
            and audited is not None and error is None
            and status['output_sha256'] == audited['output_sha256'])
