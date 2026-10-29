from pathlib import Path
import datetime
import hashlib
import importlib.util
import json
import os
import plistlib
import shutil
import sys
import traceback

REPO = Path(__file__).resolve().parents[1]
EXPECTED_HELPERS = {'wmf-block-provider-functions/macho.py': 'f6410fa931f51adbdc63bff2cd54ffcb898344fd50832a19ccbd0ba9eb8a0554', 'wmf-block-provider-functions/collect.py': '0f84b8d20b68aa1e3157646ea67891c19afb4008d3abb5eb6a3b847f4d00f9c3', 'wmf-provider-contexts/collect.py': 'ac7c508c4ab0f23d0588867e7a68c291d4acfef99b90daf7c710d66ff6cf3e93'}
for relative, digest in EXPECTED_HELPERS.items():
    assert hashlib.sha256((REPO / relative).read_bytes()).hexdigest() == digest, relative
sys.path.insert(0, str(REPO / 'wmf-block-provider-functions'))
spec = importlib.util.spec_from_file_location('wmf_existing_context_reader', REPO / 'wmf-provider-contexts/collect.py')
context = importlib.util.module_from_spec(spec)
spec.loader.exec_module(context)
parent = context.parent
MachO = context.MachO
OUT = Path('wmf-personality-provider-records')

SEEDS = {
    'dispatch': ['___dispatch_noexcept_personality', '__dispatch_client_callout',
                 '__dispatch_client_callout2', '__dispatch_client_callout3', '__dispatch_client_callout4'],
    'compiler_rt': ['___gcc_personality_v0'],
    'unwind': ['__Unwind_Resume', '__Unwind_GetLanguageSpecificData', '__Unwind_GetIP',
               '__Unwind_GetRegionStart', '__Unwind_SetGR', '__Unwind_SetIP'],
}
NEW_PATHS = {
    'compiler_rt': 'usr/lib/system/libcompiler_rt.dylib',
    'unwind': 'usr/lib/system/libunwind.dylib',
}
# This prevents repeating any already-completed selected-function query.
OLD_SELECTED_DISPATCH = [4920, 5500, 5524, 5712, 6620, 6640, 6916, 28088, 31548, 39248, 96772, 98804, 98816, 99488, 103632, 105816, 214308, 214672, 219676, 220800, 221772, 233564]


def collect_new_functions(name, image, thin, source_path):
    seeds = []
    pending = []
    for symbol_name in SEEDS[name]:
        records = [s for s in image.symbols if s['name'] == symbol_name and
                   s['type'] & 14 == 14 and not s['type'] & 0xe0]
        assert len(records) == 1, (name, symbol_name, records)
        address = records[0]['value']
        assert address in image.function_starts
        seeds.append(dict(requested_name=symbol_name, symbol=records[0], function_start=hex(address)))
        pending.append((address, 0))
    bodies = {}
    deferred = []
    while pending:
        address, depth = pending.pop(0)
        if address in bodies:
            continue
        if name == 'dispatch' and address in OLD_SELECTED_DISPATCH:
            deferred.append(dict(target=hex(address), reason='existing_completed_function_scope_reused_not_queried'))
            continue
        assert len(bodies) < 128, 'Same explicit static collection cap, not source qualification'
        body = image.function(address)
        body['collection_depth'] = depth
        bodies[address] = body
        for edge in body['direct_branches']:
            if edge['internal']:
                continue
            target = edge['target_identity']
            if target['kind'] == 'text_function_interval':
                start = int(target['function_start'], 16)
                if start in bodies:
                    continue
                if name == 'dispatch' and start in OLD_SELECTED_DISPATCH:
                    deferred.append(dict(from_function=hex(address), edge=edge,
                                         reason='existing_completed_function_scope_reused_not_queried'))
                elif depth < 2:
                    pending.append((start, depth + 1))
                else:
                    deferred.append(dict(from_function=hex(address), edge=edge,
                                         reason='outside_two_new_direct_callee_layers'))
    for address, body in sorted(bodies.items()):
        label = name + '-new-function-' + format(address, 'x')
        parent.save(label + '-complete-bits.json', body)
        parent.run(label + '-disassembly', ['xcrun', 'llvm-objdump', '--disassemble',
            '--start-address=' + body['start'], '--stop-address=' + body['end'], str(thin)])
    scope = dict(provider=name, current_path=str(source_path), UUID=image.uuid,
                 whole_file_sha256=image.whole_sha256, ARM64_slice_sha256=image.slice_sha256,
                 seeds=seeds, selected_functions=[dict(start=b['start'], end=b['end'],
                    code_sha256=b['code_sha256'], depth=b['collection_depth']) for _,b in sorted(bodies.items())],
                 deferred=deferred, new_functions=len(bodies),
                 complete_words=sum(len(b['words']) for b in bodies.values()),
                 indirect_branch_count=sum(len(b['indirect_branches']) for b in bodies.values()),
                 original_complete_call_closure_lifetime_effect_or_source_qualified=False,
                 old_selected35_not_queried_or_disassembled=True)
    parent.save(name + '-new-function-scope.json', scope)
    return scope


def main():
    OUT.mkdir()
    parent.OUT = OUT
    context.OUT = OUT
    assert os.environ.get('RUNNER_ARCH') == 'ARM64'
    assert os.environ.get('DEVELOPER_DIR') == str(parent.DEVELOPER)
    assert shutil.disk_usage(OUT).free > 512 * 1024 * 1024
    parent.run('actual-new-domain-Xcode26_5-version', ['xcodebuild', '-version'])
    settings = (parent.SDK / 'SDKSettings.json').read_bytes()
    decoded = json.loads(settings)
    assert decoded['Version'] == '26.5'
    assert decoded['SupportedTargets']['iphonesimulator']['BuildVersionPlatformID'] == '7'
    assert '17.6' in decoded['SupportedTargets']['iphonesimulator']['ValidDeploymentTargets']
    with (OUT / 'actual-new-domain-SDK26_5-Settings.json').open('xb') as f:
        f.write(settings)
    root = context.resolve_context_runtime_with_cold_start_deadline()
    version = plistlib.loads((root / 'System/Library/CoreServices/SystemVersion.plist').read_bytes())
    assert version['ProductVersion'] == '26.5' and version['ProductBuildVersion'] == '23F77'
    parent.save('actual-new-domain-runtime-version.json', version)
    references = []
    images = {}
    for name, expected in context.EXPECTED.items():
        path = root / expected['relative']
        image = MachO(path.read_bytes())
        assert image.uuid == expected['uuid']
        assert image.whole_sha256 == expected['whole_sha256']
        assert image.slice_sha256 == expected['slice_sha256']
        assert image.versions and all(v['platform'] == 7 for v in image.versions)
        references.append(dict(provider=name, path=str(path), UUID=image.uuid,
            whole_sha256=image.whole_sha256, slice_sha256=image.slice_sha256,
            prior_candidate_reference_identity_exact=True, no_original_WMF_match_granted=True))
        if name == 'dispatch':
            images[name] = (image, path)
    parent.save('actual-prior-dispatch-Blocks-file-and-slice-identity-prerequisite.json', references)
    new_contexts = []
    for name, relative in NEW_PATHS.items():
        path = root / relative
        image = MachO(path.read_bytes())
        assert image.uuid is not None and image.header['filetype'] == 6
        assert image.versions and all(v['platform'] == 7 for v in image.versions)
        images[name] = (image, path)
        parent.save(name + '-first-current-static-full-MachO-metadata.json', dict(
            identity_first_observed_in_this_domain=True, current_loaded_UUID_not_queried=True,
            path=str(path), **image.manifest()))
        new_contexts.append(context.contexts(name, dict(relative=relative, uuid=image.uuid,
            whole_sha256=image.whole_sha256, slice_sha256=image.slice_sha256), root))
    parent.save('actual-all-first-current-new-provider-identities-before-function-query.json', dict(
        at=parent.now(), new_contexts=new_contexts, new_provider_identity_from_current_static_file_not_runtime_load=True))
    temporary = Path(os.environ['RUNNER_TEMP']) / ('wmf-new-static-personality-' + os.environ['GITHUB_RUN_ID'])
    temporary.mkdir()
    scopes = []
    for name, (image, path) in images.items():
        thin = temporary / (name + '-arm64.dylib')
        with thin.open('xb') as f:
            f.write(image.data)
        scopes.append(collect_new_functions(name, image, thin, path))
    parent.save('complete-new-current-personality-static-domain.json', dict(
        at=parent.now(), run_id=os.environ['GITHUB_RUN_ID'], commit=os.environ['GITHUB_SHA'],
        image_version=os.environ.get('ImageVersion'), runtime='26.5', runtime_build='23F77',
        SDK_path=str(parent.SDK), expected_helpers=EXPECTED_HELPERS, scopes=scopes,
        all_new_runtime_and_file_identity_prerequisites_before_new_function_query=True,
        no_NeverD_DLL_CPP_owner_compilation_or_original_pipeline_or_generated_C=True,
        no_Simulator_boot_or_provider_function_or_original_WMF_execution=True,
        no_previous_inventory_probe_selected35_function_or_raw_context_job_rerun=True,
        no_Apple_provider_binary_uploaded=True,
        original_provider_implementation_lifetime_effect_or_source_qualified=False))
    print(json.dumps(dict(passed=True, providers=len(scopes),
        new_functions=sum(s['new_functions'] for s in scopes), complete_words=sum(s['complete_words'] for s in scopes))))


if __name__ == '__main__':
    try:
        main()
    except BaseException:
        if OUT.is_dir():
            parent.OUT = OUT
            parent.save('failure.json', dict(at=parent.now(), traceback=traceback.format_exc(),
                                           no_original_WMF_or_provider_function_execution=True))
        raise
