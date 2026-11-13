from pathlib import Path
import json,os,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;top=r.parent;e=top/'evidence';e.mkdir();s=top/'source'
def save(n,obj):(e/(n+'.json')).write_text(json.dumps(obj,indent=2)+'\n')
def run(args,label,check=True):
    with (e/(label+'.log')).open('wb') as f:rc=sp.run(list(map(str,args)),cwd=s,stdout=f,stderr=sp.STDOUT).returncode
    if check and rc:raise RuntimeError((label,rc,(e/(label+'.log')).read_text(errors='replace')[-2400:]))
    return rc
with tempfile.TemporaryDirectory(prefix='capstone-xcode-integration-') as tmp:
    t=Path(tmp)
    try:
        target=os.environ['CAPSTONE_XCODE_TARGET'];project=s/'xcode/Capstone.xcodeproj'
        command=['xcodebuild','-project',project,'-configuration','Release','-target',target,'-jobs','3','ONLY_ACTIVE_ARCH=YES','CODE_SIGNING_ALLOWED=NO','SYMROOT='+str(t/'out'),'OBJROOT='+str(t/'obj'),'SHARED_PRECOMPS_DIR='+str(t/'precomp'),'CLANG_MODULE_CACHE_PATH='+str(t/'modules'),'build']
        if target=='CapstoneDynamic':
            rc=run(command,'baseline',False);save('baseline',dict(status=rc))
        run(['git','apply',r/'shipping.patch'],'apply')
        run(command,'xcode')
        name={'CapstoneStatic':'libcapstone.a','CapstoneDynamic':'libcapstone.dylib','CapstoneFramework':'Capstone'}[target]
        paths=[x for x in (t/'out').rglob(name) if x.is_file() and not x.is_symlink()]
        assert len(paths)==1,paths
        lib=paths[0]
        flags=['-F',t/'out/Release','-framework','Capstone'] if target=='CapstoneFramework' else ['-I',s/'include',lib]
        run(['xcrun','clang','-O2',r/'smoke.c',*flags,'-o',t/'smoke'],'consumer-link')
        env=os.environ.copy();env.update(DYLD_LIBRARY_PATH=str(lib.parent),DYLD_FRAMEWORK_PATH=str(t/'out/Release'))
        with (e/'consumer.log').open('wb')as f:sp.run([t/'smoke'],env=env,stdout=f,stderr=sp.STDOUT,check=True)
        save('complete',dict(target=target,library=name,architectures=9))
    finally:
        n=sum(v.lstat().st_size for v in t.rglob('*') if v.is_file() and not v.is_symlink());shutil.rmtree(t);save('cleanup',dict(removed=not t.exists(),bytes=n))
