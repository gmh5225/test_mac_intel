"""Run public Ugrep suites through an admitted complete source engine."""
from pathlib import Path
import argparse
import json
import os
import platform
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parent
sys.path.insert(0,str(ROOT.parent/'runtime-helpers'))
from build import unpack
from source_engine import qualify as qualify_engine
from component_libraries import qualify as qualify_component, sha


def main():
    p=argparse.ArgumentParser();p.add_argument('--arch',choices=['arm64','x64'],required=True)
    for name in ['engine','package','output']:p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args();assert platform.system()=='Darwin' and platform.machine()=={'arm64':'arm64','x64':'x86_64'}[a.arch]
    assert subprocess.run(['/usr/sbin/sysctl','-n','sysctl.proc_translated'],capture_output=True).stdout!=b'1\n'
    engine=a.engine.resolve();package=a.package.resolve();provenance=qualify_engine(a.arch,engine);component=qualify_component('ugrep',a.arch,package)
    out=a.output.resolve();out.mkdir();logs=out/'diagnostics';logs.mkdir()
    archive=package/'source-inputs/ugrep.tar.gz';source=out/'upstream';unpack(archive,source,'ugrep-7.8.4/')
    binary=out/'ugrep';shutil.copyfile(engine,binary);binary.chmod(0o500);assert sha(binary)==provenance['binary_sha256']
    # verify.sh reads this only to select optional dependency tests. This is
    # an authored feature inventory, not a recovered producer config.h.
    features=['HAVE_PCRE2','HAVE_LIBZ','HAVE_LIBBZ2','HAVE_LIBZSTD','HAVE_LIBBROTLI','HAVE_7ZIP']
    config=out/'authored-test-features.h';config.write_text('/* Authored upstream test selection from admitted component dependencies. */\n'+''.join('#define '+name+' 1\n' for name in features))
    expected_archives={'librecovered_ugrep.a','libreflex.a','libpcre2-8.a','libz.a','libbz2.a','libzstd.a','libbrotlidec.a','libbrotlicommon.a','libviiz.a'}
    assert {v['file'] for v in component['libraries']}==expected_archives
    environment={k:v for k,v in os.environ.items() if not k.startswith('ACTIONS_') and not any(w in k.upper() for w in ['TOKEN','SECRET','PASSWORD'])}
    environment.pop('ARGV0',None);(out/'home').mkdir();(out/'tmp').mkdir()
    environment.update(HOME=str(out/'home'),TMPDIR=str(out/'tmp'),LANG='C',LC_ALL='C',UGREP_ABS_PATH=str(binary),CONFIGH_ABS_PATH=str(config),BUN_RUNTIME_TRANSPILER_CACHE_PATH='0')
    commands=[];receipt=dict(status='started',arch=a.arch,native_target_CPU=True,runtime_os_version=platform.mac_ver()[0],source_engine=provenance,component=component,
        test_feature_file_is_authored=True,features=features,commands=commands,original_executed=False,recovered_client_accepted=False,goal_complete=False)
    try:
        for label,args in [('single-thread',['-J1']),('multi-thread',[])]:
            command=['/bin/bash','verify.sh',*args];commands.append(dict(case=label,command=command))
            with (logs/(label+'.stdout')).open('xb') as stdout,(logs/(label+'.stderr')).open('xb') as stderr:
                r=subprocess.run(command,cwd=source/'tests',env=environment,stdout=stdout,stderr=stderr,timeout=900)
            commands[-1]['exit_code']=r.returncode;assert r.returncode==0,label
            text=(logs/(label+'.stdout')).read_text();assert 'ALL TESTS PASSED' in text
        receipt.update(status='native_complete_source_engine_both_ugrep_upstream_suites_passed',binary_sha256=sha(binary),ugrep_source_archive_sha256=sha(archive))
    except BaseException as error:receipt.update(status='failed_not_admitted',error_type=type(error).__name__,error=str(error));raise
    finally:(logs/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')


if __name__=='__main__':main()
