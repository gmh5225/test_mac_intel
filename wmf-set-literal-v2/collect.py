from pathlib import Path
import datetime
import hashlib
import json
import os
import plistlib
import shlex
import shutil
import subprocess
import traceback

HERE = Path(__file__).resolve().parent
P = HERE.parent / 'wmf-set-literal-v2-records'
DEVELOPER = Path('/Applications/Xcode_26.5.app/Contents/Developer')
EXPECTED_SOURCES = {'elements.swift': 'ec9c0d05074288772aa1532ff146924e942407b60b43e9755a3c6f36c0656234', 'client.swift': '20cd93e9306307c8748994f7eb203f0ba3c9e7a2f6a0bc9bffe27056d33f4dd8'}

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()

def sha(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()

def save(name, value):
    with (P / name).open('x') as stream:
        json.dump(value, stream, indent=2)
        stream.write('\n')

def run(name, argv):
    save(name + '-command.json', argv)
    started = now()
    with (P / (name + '.stdout')).open('xb') as out, (P / (name + '.stderr')).open('xb') as err:
        result = subprocess.run(argv, cwd=P, stdout=out, stderr=err)
    save(name + '-exit.json', dict(started_at=started, ended_at=now(), returncode=result.returncode))
    assert result.returncode == 0, (name, result.returncode)
    return (P / (name + '.stdout')).read_text().strip()

def dependencies(file):
    rules = []
    inputs = {}
    for line in file.read_text().replace('\\' + '\n', ' ').splitlines():
        if not line.strip():
            continue
        target, colon, body = line.partition(':')
        assert colon, (str(file), line)
        names = shlex.split(body)
        rules.append(dict(target=target, input_paths=names))
        for name in names:
            path = Path(name).resolve()
            assert path.is_file(), str(path)
            inputs[str(path)] = dict(sha256=sha(path), bytes=path.stat().st_size)
    assert rules and inputs, str(file)
    return dict(path=str(file), sha256=sha(file), rules=rules, actual_inputs=inputs)

outputs = []
try:
    P.mkdir()
    assert DEVELOPER.is_dir(), str(DEVELOPER)
    assert os.environ.get('DEVELOPER_DIR') == str(DEVELOPER)
    assert all(sha(HERE/name)==digest for name,digest in EXPECTED_SOURCES.items())
    for name in ['collect.py','elements.swift','client.swift','known-toolchain.json','README.md']:
        shutil.copyfile(HERE / name, P / name)
    save('scope.json', dict(started_at=now(), developer=str(DEVELOPER),
         repository=os.environ.get('GITHUB_REPOSITORY'), commit=os.environ.get('GITHUB_SHA'),
         run_id=os.environ.get('GITHUB_RUN_ID'), run_attempt=os.environ.get('GITHUB_RUN_ATTEMPT'),
         scope='new resilient Set literal compiler transport only; no original application or generated C',
         original_WMF_uploaded_loaded_or_executed=False, authored_machine_code_executed=False,
         original_ABI_value_frame_layout_lifetime_or_effect_permission_granted=False,
         active_compiler_limit=1))
    known = json.loads((HERE/'known-toolchain.json').read_bytes())
    swift = Path(known['identity']['swift']).resolve()
    compiler_hash = sha(swift)
    assert compiler_hash == known['identity']['swift_sha256']
    sdks = known['identity']['SDKs']
    actual_settings = {}
    for label, sdk in sdks.items():
        assert Path(sdk['path']).is_dir()
        for name, item in sdk['settings'].items():
            assert sha(item['path']) == item['sha256']
        actual_settings[label] = {name:dict(item,actual_sha256=sha(item['path']))
                                 for name,item in sdk['settings'].items()}
    save('actual-new-compiler-and-SDK-hashes-with-prior-version-reuse.json',
         dict(compiler_path=str(swift),compiler_sha256=compiler_hash,
              actual_SDK_settings=actual_settings,old_version_receipt=known,
              new_version_CLI_calls=0))
    profiles = [
        ('arm64-ios17.6-simulator', 'arm64-apple-ios17.6-simulator', 'iphonesimulator'),
        ('arm64-macos14', 'arm64-apple-macosx14.0', 'macosx'),
        ('x64-macos14', 'x86_64-apple-macosx14.0', 'macosx'),
        ('arm64-catalyst18', 'arm64-apple-ios18.0-macabi', 'macosx'),
        ('x64-catalyst18', 'x86_64-apple-ios18.0-macabi', 'macosx'),
    ]
    for label, target, sdk in profiles:
        module_dir = P/(label+'-module')
        module_dir.mkdir()
        module_output = module_dir/'NDSetExternalElements.swiftmodule'
        name = label+'-module'
        command = [str(swift),'-sdk',sdks[sdk]['path'],'-target',target,
                   '-parse-as-library','-enable-library-evolution','-O',
                   '-emit-module','-emit-dependencies','-module-name','NDSetExternalElements',
                   str(HERE/'elements.swift'),'-o',str(module_output)]
        run(name,command)
        module_dependency_files=sorted(module_dir.glob('*.d'))
        assert module_dependency_files
        module_dependencies=[dependencies(file) for file in module_dependency_files]
        dep=dict(files=module_dependencies,
                 rules=[rule for item in module_dependencies for rule in item['rules']],
                 actual_inputs={path:fact for item in module_dependencies for path,fact in item['actual_inputs'].items()})
        save(name+'-actual-dependencies.json',dep)
        item=dict(profile=label,target=target,sdk=sdk,kind='module',path=str(module_output.relative_to(P)),
                  sha256=sha(module_output),bytes=module_output.stat().st_size,
                  dependency_record=name+'-actual-dependencies.json',dependency_rules=len(dep['rules']),
                  dependency_inputs=len(dep['actual_inputs']))
        outputs.append(item);save(name+'-success.json',item)
        print(name+' first compiler PASS',flush=True)
        for kind, emit, suffix in [('IR','-emit-ir','.ll'),('SIL','-emit-sil','.sil'),('asm','-S','.s')]:
            name=label+'-'+kind
            output=P/(name+suffix)
            command=[str(swift),'-sdk',sdks[sdk]['path'],'-target',target,
                     '-parse-as-library','-enable-library-evolution','-module-name','NDExternalSetClient',
                     '-I',str(module_dir),emit,'-O','-emit-dependencies',str(HERE/'client.swift'),'-o',str(output)]
            run(name,command)
            dep=dependencies(output.with_suffix('.d'));save(name+'-actual-dependencies.json',dep)
            item=dict(profile=label,target=target,sdk=sdk,kind=kind,path=output.name,
                      sha256=sha(output),bytes=output.stat().st_size,
                      dependency_record=name+'-actual-dependencies.json',dependency_rules=len(dep['rules']),
                      dependency_inputs=len(dep['actual_inputs']))
            outputs.append(item);save(name+'-success.json',item)
            print(name+' first compiler PASS',flush=True)
    assert sha(swift) == compiler_hash
    save('actual-twenty-first-successful-module-and-client-outputs.json', outputs)
    save('review.json', dict(passed=True, finished_at=now(), compiler_commands=len(outputs),
         modules=5, IR=5, SIL=5, assembly=5, compiler_sha256=compiler_hash,
         actual_outputs=outputs, generated_machine_code_executed=False,
         original_WMF_uploaded_loaded_or_executed=False,
         original_entry_ABI_source_binding_value_layout_frame_lifetime_or_effect_qualified=False,
         no_old_provider_job_or_local_Swift612_component_rerun=True,
         formal_increment=0, active_compilers=0))
    print(json.dumps(dict(compiler_commands=len(outputs), active_compilers=0, original_execution=False)))
except BaseException:
    if P.is_dir():
        save('failure.json', dict(failed_at=now(), successful_compiler_outputs=outputs,
             active_compilers=0, traceback=traceback.format_exc()))
    raise
