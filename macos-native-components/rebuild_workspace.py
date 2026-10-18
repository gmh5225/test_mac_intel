"""Rebuild an installed private Mac workspace using its admitted public engine."""
from pathlib import Path
import argparse
import hashlib
import json
import sys

ROOT=Path(__file__).resolve().parent


def sha(path):
    with path.open('rb') as file:return hashlib.file_digest(file,'sha256').hexdigest()


def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True)
    p.add_argument('--workspace',type=Path)
    p.add_argument('--translated-compiler',action='store_true',help='Use the public x64 compiler on ARM; native execution is not accepted by this diagnostic')
    a=p.parse_args();config=json.loads((ROOT/'bundle.json').read_bytes())
    assert config['schema']=='private.source-native-macos-runtime.v1'
    for row in config['immutable_files']:
        rel=Path(row['file']);assert not rel.is_absolute() and '..' not in rel.parts and rel.as_posix()==row['file']
        file=ROOT/rel;assert file.is_file() and not file.is_symlink() and file.stat().st_size==row['bytes'] and sha(file)==row['sha256'],'Immutable input differs: '+row['file']
    output=a.output.resolve();assert not output.exists()
    logs=output.with_name(output.name+'.diagnostics');assert not logs.exists()
    workspace=(a.workspace or ROOT/'workspace').resolve()
    sys.path.insert(0,str(ROOT/'recipes/macos-native-components'))
    from client_build import build
    result=build(config['arch'],None,ROOT/'bun-source-runtime',output,logs,workspace,translated_compiler=a.translated_compiler)
    comparisons={}
    for layout,row in result['clients'].items():
        accepted=config['clients'][layout]
        equal=row['sha256']==accepted['sha256'] and row['bytes']==accepted['bytes']
        assert equal is (not bool(row['intentionally_edited_modules'])),'Unedited workspace drifted or source edits were ignored'
        comparisons[layout]=dict(client=row,matches_native_CI_bytes=equal)
    unchanged=all(row['matches_native_CI_bytes'] for row in comparisons.values())
    receipt=dict(status='unedited_layouts_match_native_CI_bytes' if unchanged else 'edited_layouts_built_and_read_back_exactly',
        comparisons=comparisons,build_receipt_sha256=sha(logs/'native-client-build.json'),
        original_input_used=False,original_native_prefix_used=False,actual_client_executed=False,
        accepted_by_prior_native_CI_byte_identity=unchanged,edited_artifacts_inherit_runtime_acceptance=False,goal_complete=False)
    (logs/'workspace-rebuild.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps(dict(status=receipt['status'],receipt=str(logs/'workspace-rebuild.json'))))


if __name__=='__main__':main()
