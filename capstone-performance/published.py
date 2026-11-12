"""Run the Capstone fork's registered native unit suites on real host CPUs."""
import json,os,platform,shutil,subprocess as sp,sys
from pathlib import Path
root=Path.cwd();e=root/'capstone-evidence';e.mkdir(exist_ok=True);w=root/'native-tests';w.mkdir();src=w/'source';b=w/'build'
revision='ebf11952991d43f44314d261707eddbd1b41141b'
def save(name,value):(e/name).write_text(json.dumps(value,indent=2)+'\n')
def run(cmd,label):
 with (e/(label+'.log')).open('w')as f:rc=sp.run(list(map(str,cmd)),stdout=f,stderr=sp.STDOUT).returncode
 if rc:print((e/(label+'.log')).read_text(errors='replace')[-3500:],flush=True);raise RuntimeError((label,rc))
try:
 target=sys.argv[1]
 run(['git','init','-q',src],'init')
 run(['git','-C',src,'fetch','--depth','1','https://github.com/NeverSight/capstone',revision],'fetch')
 run(['git','-C',src,'checkout','--detach','FETCH_HEAD'],'checkout')
 assert sp.check_output(['git','-C',src,'rev-parse','HEAD'],text=True).strip()==revision
 args=['-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCMAKE_BUILD_TYPE=Release']
 if target!='mixed':args+=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_'+target.upper()+'_SUPPORT=ON']
 run(['cmake','-G','Ninja','-S',src,'-B',b,*args],'configure')
 ctest=['ctest','--test-dir',b,'-C','Release','-R','^unit_']
 selected=json.loads(sp.check_output([*ctest,'--show-only=json-v1'],text=True))['tests']
 save('registered.json',[v['name']for v in selected]);assert len(selected)>10
 save('inputs.json',dict(revision=revision,architecture=target,host=platform.uname()._asdict(),image=os.environ['ImageVersion']))
 run(['cmake','--build',b,'--parallel','3'],'build')
 run([*ctest,'--no-tests=error','--output-on-failure','--parallel','2'],'units')
 save('complete.json',dict(complete=True,registered=len(selected)))
finally:
 size=sum(t.stat().st_size for t in w.rglob('*') if t.is_file() and not t.is_symlink())
 shutil.rmtree(w);save('cleanup.json',dict(bytes=size,removed=not w.exists()))
