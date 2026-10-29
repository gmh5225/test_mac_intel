from pathlib import Path
import datetime, hashlib, json, os, shlex, subprocess, traceback
REPO=Path(__file__).resolve().parents[1]
OUT=REPO/'wmf-lifetime-dependency-alias-records'
OUT.mkdir()
sha=lambda p:hashlib.sha256(Path(p).read_bytes()).hexdigest()
def save(name,value):
    with(OUT/name).open('x')as f:json.dump(value,f,indent=2);f.write('\n')
try:
    assert os.environ['RUNNER_ARCH']=='ARM64'
    assert os.environ['DEVELOPER_DIR']=='/Applications/Xcode_26.5.app/Contents/Developer'
    manifest=json.loads((REPO/'wmf-block-lifetime/frozen-first-build.json').read_bytes())
    assert manifest['first_run']=='40921122862'
    incoming=REPO/'wmf-frozen-first-build'
    for relative,digest in manifest['files'].items():assert sha(incoming/relative)==digest,relative
    assert not(incoming/'execute-only-new-authored-lifetime-fixture-command.json').exists()
    sdk=Path('/Applications/Xcode_26.5.app/Contents/Developer/Platforms/iPhoneSimulator.platform/Developer/SDKs/iPhoneSimulator.sdk')
    settings=(sdk/'SDKSettings.json').read_bytes()
    assert settings==(incoming/'actual-explicit-SDK26_5-Settings.json').read_bytes()
    decoded=json.loads(settings)
    assert decoded['Version']=='26.5'and decoded['SupportedTargets']['iphonesimulator']['BuildVersionPlatformID']=='7'
    assert '17.6'in decoded['SupportedTargets']['iphonesimulator']['ValidDeploymentTargets']
    with(OUT/'actual-current-SDKSettings.json').open('xb')as f:f.write(settings)
    argv=['xcodebuild','-version']
    with(OUT/'actual-Xcode26_5-version.stdout').open('xb')as out,(OUT/'actual-Xcode26_5-version.stderr').open('xb')as err:
        result=subprocess.run(argv,stdout=out,stderr=err,timeout=55)
    save('actual-Xcode26_5-version-command.json',dict(argv=argv,returncode=result.returncode,
        stdout_sha256=sha(OUT/'actual-Xcode26_5-version.stdout'),stderr_sha256=sha(OUT/'actual-Xcode26_5-version.stderr')))
    assert result.returncode==0 and(OUT/'actual-Xcode26_5-version.stdout').read_text().strip()=='Xcode 26.5\nBuild version 17F42'
    bindings=json.loads((incoming/'actual-authored-complete-compile-dependency-hashes.json').read_bytes())
    text=(incoming/'authored-current-platform7.d').read_text()
    paths=shlex.split(text.replace('\\\n',' ').split(':',1)[1])
    rows=[]
    for path in paths:
        lexical=Path(path);resolved=lexical.resolve(strict=True)
        assert lexical.is_absolute()and resolved.is_file()
        digest=sha(resolved);assert str(resolved)in bindings and bindings[str(resolved)]==digest
        assert sha(lexical)==digest
        links=[];cursor=Path(lexical.anchor)
        for part in lexical.parts[1:]:
            cursor=cursor/part
            if cursor.is_symlink():links.append(dict(path=str(cursor),target=os.readlink(cursor),resolved=str(cursor.resolve(strict=True))))
        rows.append(dict(lexical=path,canonical=str(resolved),sha256=digest,bytes=resolved.stat().st_size,symlinks=links))
    assert{r['canonical']for r in rows}==set(bindings)
    assert all(sha(path)==digest for path,digest in bindings.items())
    save('actual-all-lexical-to-canonical-current-SDK-dependency-bindings.json',rows)
    aliases=[row for row in rows if row['lexical']!=row['canonical']]
    save('actual-remote-lexical-SDK-path-aliases.json',aliases)
    save('complete-new-readonly-dependency-alias-domain.json',dict(
        at=datetime.datetime.now(datetime.timezone.utc).isoformat(),run_id=os.environ['GITHUB_RUN_ID'],commit=os.environ['GITHUB_SHA'],
        first_run='40921122862',unchanged_authored_binary_sha256=manifest['binary_sha256'],
        dependency_file_sha256=sha(incoming/'authored-current-platform7.d'),canonical_bindings_sha256=sha(incoming/'actual-authored-complete-compile-dependency-hashes.json'),
        lexical_paths=len(rows),canonical_paths=len(bindings),actual_aliases=len(aliases),
        no_compiler_IR_assembly_Simulator_NeverD_or_native_fixture_execution=True,
        no_new_provider_or_original_WMF_query=True,original_source_ABI_permission_lifetime_effect_qualified=False))
except BaseException:
    save('failure.json',dict(at=datetime.datetime.now(datetime.timezone.utc).isoformat(),traceback=traceback.format_exc()));raise
