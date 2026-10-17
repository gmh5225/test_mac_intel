"""Admit only an exact, independently qualified public source runtime."""
from pathlib import Path
import argparse,hashlib,json,shutil,struct,re,sys
ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'bun-runtime'))
from allocator_exports import versions as allocator_versions

STRATEGIES = {'single-rust-source-graph-and-c', 'single-rust-source-graph-with-c-source-libraries'}
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def load_pins():
    path=ROOT/'source-runtime-pins.json'
    data=json.loads(path.read_bytes())
    assert data['schema_version']==4 and data['integration_strategy'] in STRATEGIES, 'Pre-repair source runtime profiles are revoked'
    assert data['allocator_abi_required'] is True and data['native_rg_filename_controls_required'] is True
    assert data['profiles'], 'No qualified source-built runtime is admitted'
    assert data['status']=='allocator_abi_and_filename_controls_independently_qualified_client_acceptance_pending', 'Independent allocator qualification is missing'
    assert set(data['profiles']) <= {'x64','arm64'}
    assert type(data['producer_run']) is int and data['producer_run']>0 and re.fullmatch('[0-9a-f]{40}',data['producer_head'])
    assert data['public_bun_commit']=='c6da4a4d3010e5553438c60f6bd76d981976867c'
    for arch, selected in data['profiles'].items():
        assert selected['allocator_symbol_versions']==allocator_versions(arch)
        assert selected['native_rg_filename_control_cases']==768
        assert re.fullmatch('[0-9a-f]{64}',selected['native_rg_controls_sha256'])
        if 'ugrep_source_manifest_sha256' in selected:
            assert selected['duplicate_strong_symbols']==0
            assert re.fullmatch('[0-9a-f]{64}',selected['ugrep_private_symbol_mapping_sha256'])
            assert type(selected['ugrep_private_symbol_count']) is int and selected['ugrep_private_symbol_count']>100
    return data

def pin(arch,binary,digest):
    path=ROOT/'source-runtime-pins.json'
    data=load_pins()
    selected=data['profiles'][arch]
    assert selected['maximum_core_glibc_requirement']=='2.17'
    assert binary.is_file() and not binary.is_symlink() and sha(binary)==digest==selected['binary_sha256']
    assert binary.stat().st_size==selected['bytes']
    return dict(selected,public_bun_commit=data['public_bun_commit'],pin_file_sha256=sha(path),source_built_native_dispatch=True)
def admit(arch,artifact,output):
    data=load_pins();expected=data['profiles'][arch]
    manifest=artifact/'MANIFEST.json';assert sha(manifest)==expected['manifest_sha256']
    records=json.loads(manifest.read_bytes())['files'];seen=set()
    assert not artifact.is_symlink() and not any(p.is_symlink() for p in artifact.rglob('*'))
    for row in records:
        rel=Path(row['file']);assert not rel.is_absolute() and '..' not in rel.parts and row['file'] not in seen
        seen.add(row['file']);path=artifact/rel
        assert path.is_file() and not path.is_symlink() and path.stat().st_size==row['bytes'] and sha(path)==row['sha256']
    assert seen|{'MANIFEST.json'}=={p.relative_to(artifact).as_posix() for p in artifact.rglob('*') if p.is_file()}
    receipt=json.loads((artifact/'receipt.json').read_bytes())
    assert receipt['status']=='public_bun_source_build_and_bounded_native_dispatch_controls_passed'
    assert receipt['public_bun_commit']==data['public_bun_commit'] and receipt['arch']==arch
    bfs=data['integration_strategy']=='single-rust-source-graph-with-c-source-libraries'
    ugrep='ugrep_source_manifest_sha256' in expected
    assert not ugrep or bfs
    assert ('ugrep_source_provenance' in receipt) is ugrep
    assert receipt['maximum_core_glibc_requirement']=='2.17' and len(receipt['authored_controls'])==(18 if ugrep else 12 if bfs else 10)
    assert not receipt['original_prefix_reused'] and not receipt['captured_client_executed']
    assert not receipt['original_bun_revision_recovered']
    assert receipt['integration_strategy']==data['integration_strategy'] and receipt['zero_file_budget_controls_passed']
    assert receipt['compiled_native_archive_used'] is bfs and receipt.get('compiled_rust_archive_used',False) is False
    assert receipt['allocator_symbol_versions']==expected['allocator_symbol_versions']==receipt['source_patch']['allocator_symbol_versions']
    assert receipt['native_rg_filename_controls']==dict(status='native_rg_filename_and_inherited_fd_controls_passed',
        runtime_sha256=expected['binary_sha256'],cases=768,repetitions=32,rlimit_fsize=0)
    if bfs:
        from bfs_libraries import qualify as qualify_bfs
        library=artifact/'bfs-source-library-inputs'
        assert sha(library/'MANIFEST.json')==expected['bfs_source_manifest_sha256']
        assert qualify_bfs(arch,library,receipt['profile']['image'])==receipt['bfs_source_provenance']==receipt['source_patch']['bfs_library_provenance']
    if ugrep:
        from ugrep_libraries import qualify as qualify_ugrep
        library=artifact/'ugrep-source-library-inputs'
        assert sha(library/'MANIFEST.json')==expected['ugrep_source_manifest_sha256']
        assert qualify_ugrep(arch,library,receipt['profile']['image'])==receipt['ugrep_source_provenance']==receipt['source_patch']['ugrep_library_provenance']
        assert receipt['ugrep_exception_metadata_preserved'] and receipt['source_patch']['ugrep_exception_metadata_preserved']
        assert receipt['duplicate_strong_symbol_checks']==dict(status='zero_duplicate_strong_symbols',count=0)
        assert receipt['ugrep_source_provenance']['private_symbol_mapping_sha256']==expected['ugrep_private_symbol_mapping_sha256']
        assert receipt['ugrep_source_provenance']['private_symbol_count']==expected['ugrep_private_symbol_count']
    assert receipt['native_source_provenance']['manifest_sha256']==expected['native_source_manifest_sha256']
    assert sha(artifact/'native-component-input-manifest.json')==expected['native_source_manifest_sha256']
    assert sha(artifact/'Cargo.lock')==receipt['resolved_cargo_lock_sha256']==expected['resolved_cargo_lock_sha256']
    from verify_rust_plan import verify as verify_graph
    proof=verify_graph(artifact/'rust-plan.json')
    assert proof==receipt['rust_graph']==json.loads((artifact/'single-rust-graph.json').read_bytes())
    assert proof['plan_sha256']==expected['rust_plan_sha256']
    assert sha(artifact/'apply-seccomp.c')=='74e2ddfdef60edaf849ce13ab03def2d3ef42bf784ed79b86bab2823098f15dc'
    assert sha(artifact/'unix-block-bpf.h')=='3d435576ff6eae7ba661432c2d202464f93bdd216e294659d9e4ae50588f7f61'
    for control in receipt['authored_controls']:
        assert control['rlimit_fsize']==0 and control['exit_code']==control['expected_code'] and control['expected_text'] in control['stdout']+control['stderr']
    source=artifact/'bun';info=pin(arch,source,expected['binary_sha256'])
    raw=source.read_bytes();assert raw[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',raw,18)[0]=={'x64':62,'arm64':183}[arch]
    output.mkdir();target=output/'bun';shutil.copyfile(source,target);target.chmod(0o500)
    assert sha(target)==expected['binary_sha256']
    (output/'qualification.json').write_text(json.dumps(dict(status='qualified_public_runtime_not_client_executed',
        arch=arch,runtime_sha256=sha(target),pin=info,original_revision_recovered=False,goal_complete=False),indent=2)+'\n')
    print(json.dumps(dict(runtime_sha256=sha(target),runtime=str(target))))
if __name__=='__main__':
    ap=argparse.ArgumentParser();ap.add_argument('--arch',required=True);ap.add_argument('--artifact',type=Path,required=True);ap.add_argument('--output',type=Path,required=True);args=ap.parse_args()
    admit(args.arch,args.artifact.resolve(),args.output.resolve())
