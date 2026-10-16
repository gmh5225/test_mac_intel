"""Admit exact direct-link component artifacts before altering Bun source."""
from pathlib import Path
import hashlib,json,re,struct

ROOT=Path(__file__).resolve().parent
def sha(path):
    with path.open('rb') as stream:return hashlib.file_digest(stream,'sha256').hexdigest()
def qualify(arch,package):
    pins=json.loads((ROOT/'native-library-pins.json').read_bytes())
    assert pins['schema_version']==1 and type(pins['producer_run']) is int and pins['producer_run']>0
    assert re.fullmatch('[0-9a-f]{40}',pins['producer_head']) and set(pins['profiles'])=={'x64','arm64'}
    expected=pins['profiles'][arch]
    assert sha(package/'MANIFEST.json')==expected['manifest_sha256']
    seen=set()
    assert not package.is_symlink() and not any(p.is_symlink() for p in package.rglob('*'))
    for row in json.loads((package/'MANIFEST.json').read_bytes())['files']:
        rel=Path(row['file']);assert not rel.is_absolute() and '..' not in rel.parts and row['file'] not in seen
        seen.add(row['file']);path=package/rel
        assert path.is_file() and path.stat().st_size==row['bytes'] and sha(path)==row['sha256']
    assert seen|{'MANIFEST.json'}=={p.relative_to(package).as_posix() for p in package.rglob('*') if p.is_file()}
    receipt=json.loads((package/'receipt.json').read_bytes())
    assert sha(package/'receipt.json')==expected['receipt_sha256']
    assert receipt['status']=='direct_link_rust_and_c_candidates_pass_zero_file_budget_controls'
    assert receipt['arch']==arch and receipt['public_sources_only'] and not receipt['captured_client_executed']
    assert receipt['compiler_rust_channel']=='nightly-2026-09-15'
    assert len(receipt['controls'])==7 and all(row['rlimit_fsize']==0 for row in receipt['controls'])
    assert [row['exit_code'] for row in receipt['controls']]==[0,0,1,2,0,0,1]
    assert sha(package/'apply-seccomp.c')=='74e2ddfdef60edaf849ce13ab03def2d3ef42bf784ed79b86bab2823098f15dc'
    assert sha(package/'unix-block-bpf.h')=='3d435576ff6eae7ba661432c2d202464f93bdd216e294659d9e4ae50588f7f61'
    libraries=receipt['rust_libraries'];assert libraries
    assert sha(package/'librecovered_rg.a')==receipt['combined_library_sha256']==expected['combined_library_sha256']
    assert (package/'librecovered_rg.a').read_bytes().startswith(b'!<arch>\n')
    assert {r['file'] for r in libraries}=={p.name for p in (package/'rust-libs').iterdir()}
    for row in libraries:
        path=package/'rust-libs'/row['file']
        assert path.read_bytes().startswith(b'!<arch>\n') and sha(path)==row['sha256'] and path.stat().st_size==row['bytes']
    probe=(package/'native-role-probe').read_bytes()
    assert sha(package/'native-role-probe')==expected['probe_sha256']
    assert probe[:6]==b'\x7fELF\x02\x01' and struct.unpack_from('<H',probe,18)[0]=={'x64':62,'arm64':183}[arch]
    return dict(producer_run=pins['producer_run'],producer_head=pins['producer_head'],manifest_sha256=sha(package/'MANIFEST.json'),receipt_sha256=sha(package/'receipt.json'),combined_library_sha256=receipt['combined_library_sha256'],rust_libraries=libraries,zero_file_budget_controls=7,compiler_rust_channel=receipt['compiler_rust_channel'])
