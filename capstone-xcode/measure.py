from pathlib import Path
import hashlib,json,os,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;p=r.parent;source=p/'source';evidence=p/'xcode-evidence';evidence.mkdir()
inputs=json.loads((r/'inputs.json').read_text())
def save(name,value):(evidence/(name+'.json')).write_text(json.dumps(value,indent=2)+'\n')
def run(label,args):
    with (evidence/(label+'.log')).open('wb')as f:
        return sp.run(list(map(str,args)),cwd=source,stdout=f,stderr=sp.STDOUT).returncode
save('inputs',inputs)
save('toolchain',dict(xcode=sp.check_output(['xcodebuild','-version'],text=True),clang=sp.check_output(['clang','--version'],text=True)))
assert sp.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()==inputs['parent']
assert hashlib.sha256((r/'candidate.patch').read_bytes()).hexdigest()==inputs['sha256']
w=Path(tempfile.mkdtemp(prefix='capstone-xcode-'));results={}
try:
    for label in ['baseline','candidate']:
        if label=='candidate':
            assert run('apply',['git','apply',r/'candidate.patch'])==0
            assert run('stage',['git','add','-A'])==0
            assert sp.check_output(['git','write-tree'],cwd=source,text=True).strip()==inputs['tree']
        assert run('project-syntax-'+label,['plutil','-lint','xcode/Capstone.xcodeproj/project.pbxproj'])==0
        args=['xcodebuild','-project','xcode/Capstone.xcodeproj','-target','CapstoneStatic','-configuration','Release','-sdk','macosx','-arch','arm64','CODE_SIGNING_ALLOWED=NO','MACOSX_DEPLOYMENT_TARGET=11.0','SYMROOT='+str(w/label/'products'),'OBJROOT='+str(w/label/'objects'),'-jobs','4']
        status=run('build-'+label,args);record=dict(build_status=status)
        if not status:
            archives=list((w/label/'products').rglob('*.a'));assert len(archives)==1,archives
            record['library']=str(archives[0].relative_to(w));record['library_sha256']=hashlib.sha256(archives[0].read_bytes()).hexdigest()
            objects=list((w/label/'objects').rglob('X86VexOutput32.o'))
            record['vex32_object_count']=len(objects)
            if label=='candidate':assert objects
            executable=w/(label+'-records')
            record['link_status']=run('link-'+label,['clang','-O2','-DCAPSTONE_HAS_X86','-DCAPSTONE_USE_SYS_DYN_MEM','-Iinclude','tests/unit/x86_simple_output.c',archives[0],'-o',executable])
            if not record['link_status']:record['test_status']=run('records-'+label,[executable])
        results[label]=record;save('results',results)
    ok=all(v.get('build_status')==v.get('link_status')==v.get('test_status')==0 for v in results.values())
    save('complete',dict(success=ok,tested_tree=inputs['tree'],scope='Shipped Xcode static project, arm64 macOS, baseline and candidate full output records',results=results))
    if not ok:raise RuntimeError('Xcode project qualification failed; inspect baseline and candidate separately')
finally:
    files=[f for f in w.rglob('*')if f.is_file()];amount=sum(f.stat().st_size for f in files);shutil.rmtree(w);save('cleanup',dict(removed=not w.exists(),bytes=amount,files=len(files)))
