#!/usr/bin/env python3
"""Verify retained API evidence without network access or executing artifact code.

Requires the personal repository history containing the explicitly reviewed pins.
Original archives are retained with their GitHub SHA-256 digests. This command
checks them, published file bytes and native/process/late-failure evidence.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import re
import subprocess
import types
import zipfile
from unittest.mock import patch
import api_evidence_audit as full_audit

ORIGINAL='d61a4910cf6a05041786c979ef570ac29a054636'
EXPLICIT_EXIT='ca8da7d2045bd7b1186acfe4c3e7b1f63a66ac12'
PINS={ORIGINAL, EXPLICIT_EXIT, '4e4350ee23348c4fe9e0902ff8fb1791570086c6',
      'ac717e4288a5ff1e6ce7c93d73568e2739b9c58b', 'fb7a9d2c9cf0bb5294daf3611c74cdff54f7858b'}
WORKFLOW=None


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(content):
    return hashlib.sha256(content).hexdigest()


def same(left, right):
    return json.dumps(left,sort_keys=True)==json.dumps(right,sort_keys=True)


def object_once(pairs):
    result={}
    for key,value in pairs:
        require(key not in result,'duplicate JSON key')
        result[key]=value
    return result


def decode(content):
    return json.loads(content,object_pairs_hook=object_once)


def git_source(repo,pin,name):
    require(pin in PINS,'unreviewed parser/source pin')
    return subprocess.check_output(['git','-C',str(repo),'show',pin+':'+name],timeout=15)


def load_contract(repo,plan):
    pin=plan['source_commit']
    require(pin==plan['workflow_commit'] and pin in PINS,'source pin mismatch')
    controller=git_source(repo,pin,'scripts/intel_api_lifecycle.py')
    tree=ast.parse(controller)
    assignment,=[node for node in tree.body if isinstance(node,ast.Assign)
        and any(isinstance(target,ast.Name) and target.id=='SOURCES' for target in node.targets)]
    names=ast.literal_eval(assignment.value)
    sources={name:git_source(repo,pin,name) for name in names}
    require(plan['source_hashes']=={name:sha(content) for name,content in sources.items()},'source hashes')
    # Only explicitly reviewed immutable repository code is loaded. Artifact
    # Python files are neither imported nor evaluated.
    module=types.ModuleType('reviewed_api_contract_'+pin)
    exec(compile(sources['scripts/intel_api_contract.py'],pin+':intel_api_contract.py','exec'),module.__dict__)
    return module


def verified_files(directory):
    index=decode((directory/'files.json').read_bytes())
    require(isinstance(index,dict),'file index')
    files={}
    for name,entry in index.items():
        path=Path(name)
        require(not path.is_absolute() and '..' not in path.parts and str(path)==name,'file path')
        file=directory/path
        require(file.is_file() and not file.is_symlink() and
                file.resolve().is_relative_to(directory.resolve()),'file escapes evidence root')
        content=file.read_bytes()
        require(sha(content)==entry['sha256'],'file digest: '+name)
        files[name]=content
    actual={str(path.relative_to(directory)) for path in directory.rglob('*') if path.is_file()}
    require(actual==set(index)|{'files.json'},'unindexed evidence file')
    return files


def prefix_audit(raw,contract,guest):
    terminated=raw[:raw.rfind(b'\n')+1]
    class EndOfPrefix(Exception):pass
    readers=[]
    class Reader(contract.Reader):
        def __init__(self,values):
            super().__init__(values);self.completed=0;readers.append(self)
        def take(self,kind,**expected):
            if self.index==len(self.values):raise EndOfPrefix()
            value=super().take(kind,**expected)
            if kind=='iteration_complete':self.completed+=1
            return value
    if not terminated:
        return {'complete_iterations':0,'verified_events':0,
                'unverified_trailing_bytes':len(raw),'native_exit_verified':False}
    with patch.object(contract,'Reader',Reader):
        try:contract.audit(terminated,'vcpu',**({'guest':guest} if hasattr(contract,'GUESTS') else {}))
        except EndOfPrefix:pass
    reader,=readers
    return {'complete_iterations':reader.completed,'verified_events':reader.index,
            'unverified_trailing_bytes':len(raw)-len(terminated),'native_exit_verified':False}


def verify_native(files,audit,plan,contract):
    analyses={name:decode(files[name+'-analysis.json']) for name in ('failure','accounting')
              if name+'-analysis.json' in files}
    if 'output.log' not in files:
        require(not analyses and not any(name in files for name in
                ('result.json','native-status.json','retirement.json')),'analysis/status without original output')
        require(audit['native_passed'] is None and audit['child_retired'] is None and
                audit.get('output_sha256') is None and not audit.get('partial_progress') and
                not audit.get('verified_partial_contract'),'plan-only native facts')
        return {'native_passed':None,'child_retired':None,'completed_iterations':None,'analyses':0}
    raw=files['output.log'];native=decode(files['native-status.json'])
    require(sha(raw)==native['output_sha256']==audit['output_sha256'],'native digest')
    require(same(native,audit['native_status']) and native['command']==plan['command'] and
            native['child_retired'] is audit['child_retired'],'native process identity')
    require(decode(files['retirement.json'])==[{'pid':native['pid'],'status':native['status'],
            'retired':native['child_retired']}],'retirement identity')
    guest=plan.get('guest','timer');version=plan.get('event_version',1)
    program=decode(raw.split(b'\n',1)[0])
    require(program['version']==version,'native protocol version')
    if version>=4:
        require(program['guest']==guest and program['guest_hex']==plan['guest_hex'],'native guest identity')
    replay=error=None
    try:replay=contract.audit(raw,plan['mode'],**({'guest':guest} if version>=4 else {}))
    except ValueError as failure:error=str(failure)
    require(same(replay,audit['native_audit']) and error==audit['native_audit_error'],'native replay differs')
    if 'result.json' not in files:
        require(not analyses and audit['native_passed'] is None and
                audit['final_native_result_present'] is False,'undeclared native result or borrowed analysis')
        require(native['controller_interrupted'] is True and native['status']==-9 and
                native['child_retired'] is True and native['collection_error']=='SystemExit','unknown interruption')
        prefix=prefix_audit(raw,contract,guest)
        require(same(prefix,audit['verified_partial_contract']),'native prefix differs')
        return {'native_passed':None,'child_retired':True,
                'completed_iterations':prefix['complete_iterations'],'analyses':0}
    declared=decode(files['result.json'])
    require(same(declared['audit'],replay) and declared['audit_error']==error and
            declared['output_sha256']==sha(raw),'declared native replay')
    passed=(type(native['status']) is int and native['status']==0 and native['timed_out'] is False
            and native['child_retired'] is True and native['controller_interrupted'] is False
            and native['collection_error'] is None and replay is not None and error is None)
    require(passed is declared['passed'] and passed is audit['native_passed'] and
            declared['complete_native_acceptance'] is False,'native result changed')
    complete=replay['iterations'] if passed else None
    for name,value in analyses.items():
        if name=='failure':
            require(not passed,'failure analysis attached to pass')
            expected=inspect(raw,contract,guest)
            complete=expected.get('completed_iterations',expected.get('completed_iterations_with_corrected_framing'))
        else:expected=analyze(raw,contract,passed,guest=guest)
        require(same(value,expected),'derived '+name+' analysis differs')
    return {'native_passed':passed,'child_retired':native['child_retired'],
            'completed_iterations':complete,'analyses':len(analyses)}


def verify_run(repo,root,record):
    global WORKFLOW
    run_id=record['run_id'];require(re.fullmatch('[0-9]+',run_id) is not None,'run id')
    files=verified_files(root/run_id)
    audit=decode(files['audit.json']);snapshot=decode(files['github-status.json'])
    manifest=decode(files['artifacts.json']);plan=decode(files['prepared/plan.json'])
    full_audit.HARNESS=repo;full_audit.BASE=root
    recomputed=full_audit.audit_run(run_id)
    # Only the collector's old local manifest filename changes in the public
    # layout. All semantic and process facts must match the full archive audit.
    require(same({k:v for k,v in recomputed.items() if k!='artifact_manifest'},
                 {k:v for k,v in audit.items() if k!='artifact_manifest'}),'full archive audit differs')
    index=decode((root/run_id/'files.json').read_bytes())
    if 'workflow-logs-collection.json' in files:
        collected=decode(files['workflow-logs-collection.json'])
        require(collected['run_id']==run_id and collected['endpoint']==
                f'https://api.github.com/repos/gmh5225/test_mac_intel/actions/runs/{run_id}/logs',
                'workflow log endpoint identity')
        if collected['available']:
            blob=files['workflow-logs.zip']
            require(sha(blob)==collected['sha256'] and len(blob)==collected['bytes'],'workflow log archive digest')
            import io
            with zipfile.ZipFile(io.BytesIO(blob)) as stream:
                require(stream.namelist()==collected['files'],'workflow log inventory')
    archives={item['id']:item for item in manifest}
    required_origins={}
    for artifact in manifest:
        for member in artifact['files']:
            published=None
            if artifact['name'].endswith('-plan'):published='prepared/'+member
            elif artifact['name'].endswith('-final'):
                if not member.startswith(('progress-','prepared/')):published=member
            elif '-progress-' in artifact['name'] and member!='output-tail.log':
                published='progress/'+artifact['name'].split('-progress-',1)[1]+'/'+member
            if published:
                require(published not in required_origins,'duplicate published archive origin')
                required_origins[published]=(artifact['id'],member)
    metadata={'audit.json','artifacts.json','github-status.json','annotations.json','check-annotations.json',
              'failure-analysis.json','accounting-analysis.json','workflow-logs-collection.json','workflow-logs.zip'}
    require(set(index)-set(required_origins)<=metadata,'unrecognized non-artifact evidence')
    for name,(artifact_id,member) in required_origins.items():
        require(name in index and index[name].get('artifact_id')==artifact_id and
                index[name].get('archive_member')==member,'missing or changed required artifact origin')
    for name,entry in index.items():
        if 'artifact_id' not in entry:continue
        require(entry['artifact_id'] in archives,'unknown artifact origin')
        artifact=archives[entry['artifact_id']];member=entry['archive_member']
        require(member in artifact['files'],'unknown artifact member')
        if artifact['name'].endswith('-plan'):expected='prepared/'+member
        elif artifact['name'].endswith('-final'):expected=member
        else:expected='progress/'+artifact['name'].split('-progress-',1)[1]+'/'+member
        require(expected==name,'published artifact member mapping')
        with zipfile.ZipFile(root/'archives'/f"{artifact['id']}.zip") as stream:
            require(files[name]==stream.read(member),'published bytes differ from original archive')
    for key in ('run_id','workflow_commit','helper_commit','mode','image','workflow_conclusion',
            'native_passed','child_retired','verified_artifacts','native_audit',
            'verified_partial_contract','matched_uploader_crashes','output_sha256','output_bytes'):
        require(same(record[key],recomputed.get(key)),'summary differs: '+key)
    require(record['observation']==plan.get('observation','live'),'summary observation mode')
    if 'guest' in plan:require(record['guest']==plan['guest'],'summary guest')
    else:require('guest' not in record,'legacy summary guest relabelled')
    WORKFLOW=audit['workflow_commit'];require(WORKFLOW in PINS,'unreviewed workflow')
    verify_server_identity(snapshot,manifest,run_id)
    require(audit['run_id']==run_id==plan['run_id'] and audit['workflow_status']=='completed' and
            snapshot['run']['status']=='completed' and
            audit['workflow_conclusion']==snapshot['run']['conclusion']==record['workflow_conclusion'],
            'terminal run identity')
    require(audit['verified_artifacts']==len(manifest)==record['verified_artifacts'],'archive inventory')
    require(same(plan,audit['plan']) and plan['workflow_commit']==WORKFLOW and
            plan['run_attempt']==str(snapshot['run']['run_attempt']) and
            plan['runner_image']==audit['image']==record['image'],'sealed plan identity')
    require(plan['complete_native_acceptance'] is False and audit['complete_native_acceptance'] is False and
            record['complete_native_acceptance'] is False,'acceptance scope')
    if 'plan.json' in files:require(files['plan.json']==files['prepared/plan.json'],'changed final plan')
    contract=load_contract(repo,plan)
    if WORKFLOW==EXPLICIT_EXIT:
        content=files['check-annotations.json']
        require(sha(content)==audit['check_annotations_sha256'],'annotation envelope digest')
        annotations=verify_check_annotations(snapshot,decode(content),decode(files['annotations.json']))
        lost=any('The hosted runner lost communication with the server' in item['message'] for item in annotations)
        require(lost is audit['runner_loss_explicitly_reported'] and
                lost is record['runner_loss_explicitly_reported'],'runner loss classification')
        timed_out=any(item['message']=='The job has exceeded the maximum execution time of 30m0s'
                      for item in annotations)
        require(timed_out is audit['job_timeout_explicitly_reported'] and
                timed_out is record['job_timeout_explicitly_reported'],'job timeout classification')
    result=verify_native(files,audit,plan,contract)
    require(result['native_passed'] is record['native_passed'] and
            result['child_retired'] is record['child_retired'],'summary native outcome')
    for name,key in [('failure','supplemental_failure_analysis'),('accounting','reported_accounting')]:
        if name+'-analysis.json' in files:
            require(same(record[key],decode(files[name+'-analysis.json'])),'summary analysis')
        else:require(key not in record,'summary has analysis without this run raw sidecar')
    require(record['workflow_commit']==WORKFLOW and
            record['url']==snapshot['run']['html_url'],'summary source/run identity')
    return {'run_id':run_id,'verified_files':len(files),**result}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--repository',type=Path,default=Path(__file__).resolve().parents[1])
    parser.add_argument('--evidence',type=Path)
    args=parser.parse_args()
    root=args.evidence or args.repository/'results/2026-10-05-api-lifecycle'
    summary=decode((root/'summary.json').read_bytes())
    require(summary['complete_native_acceptance'] is False,'summary acceptance scope')
    records=summary['runs'];ids=[record['run_id'] for record in records]
    require(len(ids)==len(set(ids)),'duplicate run id')
    require(set(ids)=={path.name for path in root.iterdir() if path.is_dir() and path.name.isdecimal()},
            'omitted published run')
    results=[verify_run(args.repository,root,record) for record in records]
    expected_archives={str(item['id'])+'.zip' for run_id in ids
        for item in decode((root/run_id/'artifacts.json').read_bytes())}
    require(expected_archives=={path.name for path in (root/'archives').iterdir()},'original archive inventory')
    print(json.dumps({'runs':results,'verified_files':sum(run['verified_files'] for run in results),
        'verified_archives':len(expected_archives),
        'complete_native_acceptance':False,
        'scope':'Full offline original-archive, file, process, budget and historical native protocol replay. This does not establish complete NeverD acceptance.'},indent=2))




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


def inspect(raw, contract, guest='timer'):
    contract.require(raw.endswith(b'\n') and len(raw)<=32*1024*1024, 'output framing/budget')
    values=[]
    def reject(value):raise ValueError('non-integer number: '+value)
    for line in raw.split(b'\n')[:-1]:
        item=json.loads(line,object_pairs_hook=contract._object,parse_float=reject,parse_constant=reject)
        contract.require(type(item) is dict, 'event object')
        for key in contract.COMMON-{'event'}:
            contract.require(type(item.get(key)) is int and 0<=item[key]<2**64,'common integer')
        values.append(item)
    contract.require(0<len(values)<=contract.EVENT_LIMIT,'event budget')
    version=values[0]['version']
    readers=[]
    class RecordedReader(contract.Reader):
        def __init__(self,events):
            super().__init__(events);self.completed=0;readers.append(self)
        def take(self,kind,**expected):
            item=super().take(kind,**expected)
            if kind=='iteration_complete':self.completed+=1
            return item
    error=None
    with patch.object(contract,'Reader',RecordedReader), patch.object(contract,'records',lambda _:values):
        try:contract.audit(raw,'vcpu',**({'guest':guest} if version>=4 else {}))
        except ValueError as failure:error=str(failure)
    contract.require(error=='late or nonmonotonic call/capture','expected specific late failure')
    reader,=readers
    measured=values[reader.index-1] if version>=3 else None
    offset=1 if measured else 0
    begin,returned,captured=values[reader.index-3-offset:reader.index-offset]
    contract.require([v['event'] for v in (begin,returned,captured)]==['call_begin','call_end','capture'],'failed triplet')
    budget=next(v for v in reversed(values[:reader.index]) if v['event']=='budget')
    # The historical parser groups late and reversed clocks in one error.
    # Only the deadline upper bound may be exceeded in this analysis; never
    # interpret invalid admission or a negative interval as a late return.
    prior=values[:reader.index-3-offset]
    previous_kind='accounting' if version>=3 else 'capture'
    previous_key='post_finished' if version>=3 else 'captured'
    previous=next((v[previous_key] for v in reversed(prior)
                   if v['event']==previous_kind and v['iteration']==reader.iteration),budget['start'])
    entered=returned['entered'] if version>=2 else begin['before']
    contract.require(previous<=begin['before']<=entered<budget['end'] and
                     entered<=returned['after']<=captured['captured'],
                     'late analysis requires valid admission and monotonic time')
    contract.require(returned['after']>budget['end'] and captured['captured']>budget['end'],'late return and capture')
    target=contract.GUESTS[guest][1] if version>=4 else 52
    pair=(captured['rip'],captured['witness'])
    contract.require(captured['reason'] in (1,52,target) and
                     pair in ((0x100,0),(0x103,reader.iteration)), 'late exit or witness is invalid')
    contract.require(captured['reason']!=12 or pair==(0x103,reader.iteration),'late HLT lacks fresh store')
    saw_store=any(v['event']=='capture' and v['iteration']==reader.iteration and
                  v['witness']==reader.iteration for v in prior)
    contract.require(not saw_store or pair==(0x103,reader.iteration),'late guest progress regressed')
    reader.take('error',operation='late_or_nonmonotonic_capture',status=begin['call'])
    for resource in ('cpu_destroy','unmap','vm_destroy'):reader.resource(resource)
    reader.take('backing_released')
    contract.require(reader.index==len(values),'failure suffix')
    program=values[0]
    numer,denom=program['timebase_numer'],program['timebase_denom']
    result={'kind':'supplemental-LF-framing-failure-analysis','native_passed':False,
        'complete_native_acceptance':False,'original_bytes_unchanged':True,
        'output_sha256':hashlib.sha256(raw).hexdigest(),
        'scope':'Correct LF framing of JSON whitespace; original runtime audit and failure retained. Old intervals include log writes and host scheduling, not isolated HVF execution.',
        'completed_iterations_with_corrected_framing':reader.completed,'failed_iteration':reader.iteration,
        'failed_call':begin['call'],'fixed_budget_ns':contract.BUDGET_NS,
        'begin_to_return_ns':(returned['after']-begin['before'])*numer//denom,
        'budget_start_to_capture_ns':(captured['captured']-budget['start'])*numer//denom,
        'reason':captured['reason'],'rip':captured['rip'],'rax':captured['rax'],'witness':captured['witness'],
        'checked_cleanup_order':['cpu_destroy','unmap','vm_destroy','backing_released'],
        'native_resource_retirement_records_verified':True,
        'crcrlf_terminators':raw.count(b'\r\r\n')}
    if program['version']>=2:
        result['kind']=f'native-version-{version}-failure-analysis'
        result['scope']='Original LF records and version-2 event contract. Pre-call/return interval excludes log writes but includes host scheduling; it is not proof of VM entry or isolated guest CPU time.'
        result['completed_iterations']=result.pop('completed_iterations_with_corrected_framing')
        result['begin_log_interval_ns']=(returned['entered']-begin['before'])*numer//denom
        result['precall_to_return_ns']=(returned['after']-returned['entered'])*numer//denom
        result['return_to_capture_ns']=(captured['captured']-returned['after'])*numer//denom
    if measured:
        result['scope']=f'Original version-{version} failure including validated cumulative Intel HVF and Darwin thread CPU counters. Neither reported counter nor differences between clocks establish physical guest execution, host scheduling duration or a root cause.'
        result['accounting']=measured
        result['begin_log_interval_ns']=(measured['pre_started']-begin['before'])*numer//denom
        result['pre_sample_width_ns']=(measured['pre_finished']-measured['pre_started'])*numer//denom
        result['post_sample_width_ns']=(measured['post_finished']-measured['post_started'])*numer//denom
        result['reported_exec_delta_ns']=measured['exec_after_ns']-measured['exec_before_ns']
        result['reported_thread_delta_ns']=measured['thread_after_ns']-measured['thread_before_ns']
    if version>=4:
        result['guest']=guest
        result['target_exit_observed']=captured['reason']==contract.GUESTS[guest][1]
    return result


def analyze(raw,contract,passed,iterations=1000,guest='timer'):
    values=contract.records(raw)
    program=values[0]
    version=program['version']
    if passed:
        complete=contract.audit(raw,'vcpu',iterations,**({'guest':guest} if version>=4 else {}))['iterations']
    else:
        complete=inspect(raw,contract,guest)['completed_iterations']
    contract.require(version in (3,4),'accounting protocol version')
    numer,denom=program['timebase_numer'],program['timebase_denom']
    ns=lambda ticks:ticks*numer//denom
    calls=[]
    for index,item in enumerate(values):
        if item['event']!='accounting':continue
        begin,returned,captured=values[index-3:index]
        contract.require([v['event'] for v in (begin,returned,captured)]==
                         ['call_begin','call_end','capture'],'accounting call group')
        calls.append({'iteration':item['iteration'],'call':item['call'],
            'precall_to_return_ns':ns(returned['after']-returned['entered']),
            'begin_log_interval_ns':ns(item['pre_started']-begin['before']),
            'return_to_capture_ns':ns(captured['captured']-returned['after']),
            'pre_sample_width_ns':ns(item['pre_finished']-item['pre_started']),
            'post_sample_width_ns':ns(item['post_finished']-item['post_started']),
            'reported_exec_delta_ns':item['exec_after_ns']-item['exec_before_ns'],
            'reported_thread_delta_ns':item['thread_after_ns']-item['thread_before_ns'],
            'reason':captured['reason'],'rip':captured['rip'],'witness':captured['witness']})
    contract.require(bool(calls),'no validated accounting')
    result={'kind':'validated-Intel-HVF-and-Darwin-reported-accounting',
        'event_version':version,'native_passed':passed,'complete_native_acceptance':False,
        'output_sha256':hashlib.sha256(raw).hexdigest(),
        'completed_iterations':complete,'observed_calls':len(calls),
        'largest_pre_call_intervals':sorted(calls,key=lambda call:call['precall_to_return_ns'],reverse=True)[:3],
        'scope':'Each counter delta spans its getter samples, including different small setup/capture overheads. The pre-call interval excludes those getters and logs but includes scheduling. These reported counters in nested macOS do not prove physical guest CPU time, scheduling duration, kernel root cause or a performance improvement.'}
    if version>=4:result['guest']=guest
    return result


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


if __name__=='__main__':main()
