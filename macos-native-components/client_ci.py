"""Two private client builds and native offline acceptance; export safe evidence only."""
from pathlib import Path
import argparse
import base64
import hashlib
import json
import shutil
import subprocess
import sys
import tarfile

ROOT=Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'bun-runtime'))
from native_libraries import check_manifest
from client_build import build
from client_acceptance import Harness, sha, write


def published_input(arch, folder):
    folder.mkdir(); pin=json.loads((ROOT/'original-pins.json').read_bytes())[arch]
    archive=folder/'published-input.tgz'
    result=subprocess.run(['curl','--http1.1','--fail','--silent','--show-error','--location','--retry','3','--max-time','300',
        '--max-filesize','134217728','--output',str(archive),pin['url']],capture_output=True,timeout=360)
    assert result.returncode==0,'published input download failed'
    with archive.open('rb') as file: assert 'sha512-'+base64.b64encode(hashlib.file_digest(file,'sha512').digest()).decode()==pin['integrity']
    original=folder/'original'
    with tarfile.open(archive,'r:gz') as source:
        members=[m for m in source.getmembers() if m.name=='package/claude' and m.isfile()]
        assert len(members)==1 and members[0].size==pin['bytes']
        with source.extractfile(members[0]) as raw,original.open('xb') as output:shutil.copyfileobj(raw,output)
    assert original.stat().st_size==pin['bytes'] and sha(original)==pin['sha256'];original.chmod(0o500)
    return original


def main():
    p=argparse.ArgumentParser();p.add_argument('--arch',choices=['arm64','x64'],required=True)
    for name in ['package','output','logs']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();output=a.output.resolve();logs=a.logs.resolve();output.mkdir();logs.mkdir()
    pins=json.loads((ROOT/'source-engine-pins.json').read_bytes());pin=pins['profiles'][a.arch]
    package=a.package.resolve();check_manifest(package,pin['package_manifest_sha256'])
    engine=package/'bun';assert sha(engine)==pin['binary_sha256']
    original=published_input(a.arch,output/'published-input')
    receipt=dict(status='started',arch=a.arch,source_engine_sha256=sha(engine),original_sha256=sha(original),
        client_binaries_uploaded=False,captured_source_uploaded=False,builds=[],goal_complete=False)
    try:
        for number in [1,2]:
            work=output/('private-build-'+str(number));diagnostics=output/('private-build-logs-'+str(number))
            result=build(a.arch,original,engine,work,diagnostics)
            receipt['builds'].append(result);write(logs/('build-'+str(number)+'.json'),result)
            for layout in ['preserved','readable']:
                public=logs/('build-'+str(number)+'-'+layout);public.mkdir()
                shutil.copyfile(work/layout/'mapping.tsv',public/'selected-module-hashes.tsv')
                shutil.copyfile(work/layout/'readback/mapping.tsv',public/'readback-module-hashes.tsv')
                for name in ['boundary.result.json','boundary.stdout','compile-source.result.json','readback.stdout','build-profile.sb']:
                    shutil.copyfile(diagnostics/(layout+'-'+name),public/name)
        first,second=receipt['builds']
        assert {k:r['sha256'] for k,r in first['clients'].items()}=={k:r['sha256'] for k,r in second['clients'].items()}
        receipt['two_independent_builds_identical']=True
        harness=Harness(a.arch,original,engine,output/'private-build-logs-1/native-client-build.json',output/'private-client-runs',logs/'client')
        try:
            harness.qualify_fixture();harness.version();harness.tool_matrix('search');harness.tool_matrix('core');harness.configuration()
            assert all(sha(path)==harness.receipt['client_sha256'][label] for label,path in harness.clients.items())
            harness.receipt.update(status='selected_native_Mac_client_differential_cases_passed',inputs_preserved=True,groups=['version','search','core','config'])
        except Exception as error:
            harness.receipt.update(status='failed_private_records_retained',error_type=type(error).__name__);raise
        finally:write(harness.logs/'client-acceptance.json',harness.receipt)
        receipt.update(status='both_native_Mac_client_layouts_twice_built_read_back_and_actual_cases_passed',
            client_acceptance_sha256=sha(harness.logs/'client-acceptance.json'),differential_pairs=len(harness.receipt['differential_pairs']))
    except Exception as error:
        receipt.update(status='failed_private_inputs_excluded_from_upload',error_type=type(error).__name__);raise
    finally:write(logs/'receipt.json',receipt)


if __name__=='__main__':main()
