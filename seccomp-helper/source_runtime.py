"""Admit only an exact, independently qualified public source runtime."""
from pathlib import Path
import argparse,hashlib,json,shutil,struct
ROOT=Path(__file__).resolve().parent
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def pin(arch,binary,digest):
    path=ROOT/'source-runtime-pins.json'
    data=json.loads(path.read_bytes())
    assert data['schema_version']==1 and data['producer_run']==38956750121
    assert data['producer_head']=='eb8533774208375903ddc7d298278626e5ac1cce'
    assert data['public_bun_commit']=='c6da4a4d3010e5553438c60f6bd76d981976867c'
    selected=data['profiles'][arch]
    assert selected['maximum_core_glibc_requirement']=='2.17'
    assert binary.is_file() and not binary.is_symlink() and sha(binary)==digest==selected['binary_sha256']
    assert binary.stat().st_size==selected['bytes']
    return dict(selected,public_bun_commit=data['public_bun_commit'],pin_file_sha256=sha(path),source_built_native_dispatch=True)
def admit(arch,artifact,output):
    data=json.loads((ROOT/'source-runtime-pins.json').read_bytes());expected=data['profiles'][arch]
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
    assert receipt['maximum_core_glibc_requirement']=='2.17' and len(receipt['authored_controls'])==8
    assert not receipt['original_prefix_reused'] and not receipt['captured_client_executed']
    assert not receipt['original_bun_revision_recovered']
    assert len(receipt['payloads'])==2 and all(row['static_without_interpreter'] for row in receipt['payloads'])
    assert {row['name']:row['sha256'] for row in receipt['payloads']}==expected['embedded_payloads']
    for control in receipt['authored_controls']:
        assert control['exit_code']==control['expected_code'] and control['expected_text'] in control['stdout']+control['stderr']
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
