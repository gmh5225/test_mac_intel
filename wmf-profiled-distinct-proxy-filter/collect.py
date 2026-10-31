from pathlib import Path
import datetime, hashlib, json, os, shlex, shutil, subprocess, traceback
HERE=Path(__file__).resolve().parent
P=HERE.parent/'wmf-profiled-distinct-proxy-filter-records'
DEVELOPER=Path('/Applications/Xcode_26.5.app/Contents/Developer')
EXPECTED_CLIENT='a4cec51c8c0f3e411b23aa22ac0259025e8cf7afc49c3260011291ff7a231596'
EXPECTED_ELEMENTS='ec9c0d05074288772aa1532ff146924e942407b60b43e9755a3c6f36c0656234'
def now():return datetime.datetime.now(datetime.timezone.utc).isoformat()
def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda:stream.read(1048576),b''):h.update(block)
    return h.hexdigest()
def save(n,v):
    with (P/n).open('x') as f:json.dump(v,f,indent=2);f.write('\n')
def run(name,argv):
    save(name+'-command.json',argv);started=now()
    with (P/(name+'.stdout')).open('xb') as out,(P/(name+'.stderr')).open('xb') as err:r=subprocess.run(argv,cwd=P,stdout=out,stderr=err)
    save(name+'-exit.json',dict(started_at=started,ended_at=now(),returncode=r.returncode));assert r.returncode==0,(name,r.returncode)
def dependencies(path):
    rules=[];inputs={}
    for line in path.read_text().replace('\\\n',' ').splitlines():
        if not line.strip():continue
        target,sep,body=line.partition(':');assert sep
        paths=shlex.split(body);rules.append(dict(target=target,input_paths=paths))
        for name in paths:
            p=Path(name).resolve();assert p.is_file(),p;inputs[str(p)]=dict(sha256=sha(p),bytes=p.stat().st_size)
    assert rules and inputs
    return dict(path=str(path),sha256=sha(path),rules=rules,actual_inputs=inputs)
outputs=[]
try:
    P.mkdir();assert DEVELOPER.is_dir() and os.environ.get('DEVELOPER_DIR')==str(DEVELOPER)
    assert sha(HERE/'client.swift')==EXPECTED_CLIENT and sha(HERE/'elements.swift')==EXPECTED_ELEMENTS
    for name in ['collect.py','client.swift','elements.swift','known-toolchain.json','reused-modules.json','README.md']:shutil.copyfile(HERE/name,P/name)
    known=json.loads((HERE/'known-toolchain.json').read_bytes());swift=Path(known['identity']['swift']).resolve();compiler_hash=sha(swift)
    assert compiler_hash==known['identity']['swift_sha256']=='3fb2fc53bc6d89a96e074bead6384a540e25f7cbffec62c4f028fe24ba01540f'
    sdks=known['identity']['SDKs'];actual={}
    for label,sdk in sdks.items():
        assert Path(sdk['path']).is_dir()
        for name,v in sdk['settings'].items():assert sha(v['path'])==v['sha256']
        actual[label]={name:dict(v,actual_sha256=sha(v['path'])) for name,v in sdk['settings'].items()}
    save('actual-matching-compiler-SDK-hashes-and-reused-version-text.json',dict(compiler_path=str(swift),compiler_sha256=compiler_hash,actual_SDK_settings=actual,reused_old_version_receipt=known,new_version_CLI=0))
    mods=json.loads((HERE/'reused-modules.json').read_bytes())['modules'];assert len(mods)==5
    for m in mods:
        path=HERE/m['path'];assert sha(path)==m['sha256'] and path.stat().st_size==m['bytes']
        target=P/'reused-module-inputs'/m['profile']/'NDSetExternalElements.swiftmodule';target.parent.mkdir(parents=True);shutil.copyfile(path,target)
    save('scope.json',dict(started_at=now(),repository=os.environ.get('GITHUB_REPOSITORY'),commit=os.environ.get('GITHUB_SHA'),run_id=os.environ.get('GITHUB_RUN_ID'),run_attempt=os.environ.get('GITHUB_RUN_ATTEMPT'),new_client_sha256=EXPECTED_CLIENT,fixed_opposite_inline_proxy_predicates=True,new_profile_generate_mode=True,same_Swift_source_bytes_as_completed_unprofiled6479=True,old_five_authored_modules_hash_reused=True,new_modules_compiled=0,planned_compiler_CLI=15,planned_IR=5,planned_SIL=5,planned_assembly=5,only_authored_source_and_authored_old_modules_uploaded=True,original_WMF_uploaded_loaded_or_executed=False,authored_machine_or_generated_C_executed=False,Simulator_launched=False,original_ABI_entry_callback_return_value_layout_frame_borrow_noescape_ownership_lifetime_effects_or_source_permissions=False,active_compiler_limit=1))
    for m in mods:
        for kind,emit,suffix in [('IR','-emit-ir','.ll'),('SIL','-emit-sil','.sil'),('asm','-S','.s')]:
            name=m['profile']+'-'+kind;output=P/(name+suffix);assert not output.exists()
            argv=[str(swift),'-sdk',sdks[m['sdk']]['path'],'-target',m['target'],'-parse-as-library','-enable-library-evolution','-profile-generate','-module-name','NDProfiledResilientProxySetFilter','-I',str((HERE/m['path']).parent),emit,'-O','-emit-dependencies',str(HERE/'client.swift'),'-o',str(output)]
            run(name,argv);dep=dependencies(output.with_suffix('.d'));save(name+'-actual-dependencies.json',dep)
            item=dict(profile=m['profile'],target=m['target'],sdk=m['sdk'],kind=kind,path=output.name,sha256=sha(output),bytes=output.stat().st_size,dependency_record=name+'-actual-dependencies.json',dependency_rules=len(dep['rules']),dependency_inputs=len(dep['actual_inputs']))
            outputs.append(item);save(name+'-success.json',item);print(name+' first compiler PASS',flush=True)
    assert len(outputs)==15 and sha(swift)==compiler_hash
    for m in mods:assert sha(HERE/m['path'])==m['sha256']
    save('actual-fifteen-first-successful-new-profiled-distinct-proxy-filter-outputs.json',outputs)
    save('review.json',dict(passed=True,finished_at=now(),compiler_commands=15,new_modules=0,old_modules_hash_reused=5,IR=5,SIL=5,assembly=5,new_version_CLI=0,compiler_sha256=compiler_hash,actual_outputs=outputs,original_WMF_uploaded_loaded_or_executed=False,authored_machine_generated_C_executed=False,Simulator_launched=False,old_successful_jobs_or_modules_restarted=False,original_entry_callback_return_ABI_value_layout_frame_lifetime_effects_or_source_granted=False,formal_increment=0,native_global_increment=0,active_compilers=0))
    print(json.dumps(dict(compiler_commands=15,active_compilers=0,original_execution=False)),flush=True)
except BaseException:
    if P.is_dir():save('failure.json',dict(failed_at=now(),successful_compiler_outputs=outputs,active_compilers=0,traceback=traceback.format_exc()))
    raise
