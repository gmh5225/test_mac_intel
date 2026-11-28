import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

here = Path.cwd()
runner = here/'neverd-joined-software'
project = here/'project'
reports = here/'reports'
reports.mkdir()
build = project/'build-signing-joins'
cfg = json.loads((runner/'source.def').read_text())
recipe = json.loads((project/'scripts/verify_arm64e_x1_projections.def').read_text())['r6']
def capture(*command):
    return subprocess.check_output(command,cwd=project,text=True).strip()
def run(command, cwd=project, env=None):
    print(subprocess.list2cmdline([str(x) for x in command]), flush=True)
    subprocess.run(command,cwd=cwd,env=env,check=True)
assert capture('git','rev-parse','HEAD')==cfg['revision']
metadata=dict(revision=cfg['revision'],platform=capture('sw_vers','-productVersion'),cpu=capture('sysctl','-n','machdep.cpu.brand_string'),architecture=capture('uname','-m'),compiler=capture('xcrun','clang','--version').splitlines()[0],llvm_prebuilt=recipe['tag'],sdk_sha256=recipe['sha256'])
(reports/'host.json').write_text(json.dumps(metadata,indent=2)+'\n')
assert metadata['architecture']=='arm64'
if not shutil.which('ninja'):
    run(['brew','install','ninja'])
run(recipe['dependencies'])
run([arg.format(build=build,**recipe) for arg in recipe['configure']])
run([sys.executable,'scripts/build.py',build,'--target',cfg['image_target'],cfg['unwind_target'],cfg['discovery_target'],'--parallel','3'])
shutil.copyfile(build/'neverd-build-receipt.json',reports/'receipt.json')
env=dict(os.environ,NEVERD_ARM64E_PERSONALITY_NATIVE='1',NEVERD_THREADS='1',NEVERD_SIGNATURE_CACHE='off',PYTHONDONTWRITEBYTECODE='1')
image=build/'bin'/cfg['image_target']
unwind=build/'bin'/cfg['unwind_target']
def suite(exe,name,expected,extra=()):
    output=reports/(name+'.json')
    run([exe,*extra,'--gtest_output=json:'+str(output)],env=env)
    report=json.loads(output.read_text())
    assert report['tests']==expected and report['failures']==report['errors']==report['disabled']==0
    assert all(c['result']=='COMPLETED' and not c.get('skipped') for s in report['testsuites'] for c in s['testsuite'])
suite(unwind,'portable',cfg['unwind_count'])
suite(build/'bin'/cfg['discovery_target'],'discovery',cfg['discovery_count'],['--gtest_filter='+cfg['discovery_filter']])
run(['ctest','--test-dir',build,'-C','Release','-L','^'+cfg['unwind_target']+'$','--no-tests=error','--output-on-failure','-j2'],env=env)
run([sys.executable,'scripts/verify_arm64e_return_model.py','build-signing-address','--joins','--tests',image,'--output',reports/'guests'],env=env)
suite(image,'other',cfg['other_count'],['--gtest_filter=*-AArch64AsyncUnwind.*:AArch64LiftedImage.*'])
run([sys.executable,runner/'images.py',image],cwd=here,env=env)
with unwind.open('rb') as f:
    metadata['unwind_test_sha256']=hashlib.file_digest(f,'sha256').hexdigest()
metadata['release_test_sha256']=json.loads((reports/'hosted-images.json').read_text())['binary_sha256']
(reports/'host.json').write_text(json.dumps(metadata,indent=2)+'\n')

cases = json.loads((reports/'hosted-images.json').read_text())['cases']
for name, expected in cfg['required_image_properties'].items():
    assert all(int(cases[name][key]) == count for key, count in expected.items())
