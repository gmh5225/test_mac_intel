from pathlib import Path
import hashlib,json,os,platform,shutil,subprocess as sp,sys,tempfile
r=Path(__file__).resolve().parent;root=r.parent;s=root/'source';out=root/'evidence';out.mkdir();conf=os.environ['PROFILE'];cc=os.environ['CC'];win=platform.system()=='Windows'
def write(n,d):(out/(n+'.json')).write_text(json.dumps(d,indent=2)+'\n')
def run(a,n):
 with (out/(n+'.log')).open('wb')as f:z=sp.run(list(map(str,a)),stdout=f,stderr=sp.STDOUT)
 if z.returncode:print((out/(n+'.log')).read_text(errors='replace')[-2200:],flush=True);z.check_returncode()
def g(*a):return sp.check_output(['git','-C',s,*a],text=True).strip()
m=json.loads((r/'tree.json').read_text())
payload=sp.check_output(['git','-C',root,'cat-file','blob','HEAD:scan-abi/candidate.patch'])
assert g('rev-parse','HEAD')==m['parent'] and hashlib.sha256(payload).hexdigest()==m['sha256']
t=Path(tempfile.mkdtemp());b=t/'build'
try:
 patch=t/'canonical.patch';patch.write_bytes(payload);g('apply','--cached',str(patch));assert g('write-tree')==m['tree']
 for file in g('diff','--cached','--name-only','HEAD').splitlines():
  raw=sp.check_output(['git','-C',s,'show',':'+file]);(s/file).write_bytes(raw)
 opts=['-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER='+cc,'-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_X86_SUPPORT=ON','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_STATIC_MSVC_RUNTIME=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF']
 if conf=='adapter':opts.append('-DCAPSTONE_X86_SCAN_ADAPTER=ON')
 if conf=='diet':opts.append('-DCAPSTONE_BUILD_DIET=ON')
 if conf=='reduce':opts.append('-DCAPSTONE_X86_REDUCE=ON')
 if conf=='full' and not win:opts.append('-DCAPSTONE_ARM_SUPPORT=ON')
 run(['cmake','-S',s,'-B',b,*opts],'configure')
 tests=['x86_scan_batch','text_option','detail_option']
 if conf not in ('diet','reduce'):tests.extend(['x86_simple_output','x86_buffer_bounds'])
 if conf=='adapter':tests.append('x86_scan_adapter')
 run(['cmake','--build',b,'--parallel','4','--target','capstone_static',*tests],'build')
 run(['ctest','--test-dir',b,'--no-tests=error','--output-on-failure','-R','^unit_('+'|'.join(tests)+')$'],'units')
 run([sys.executable,'-B',s/'suite/synctools/x86_operand_specializations.py','--check'],'operand-generator')
 lib,=list(b.rglob('capstone.lib' if win else 'libcapstone.a'));exe=t/('check.exe'if win else 'check')
 if win:args=['cl','/nologo','/O2','/MT','/std:c11','/I'+str(s),'/I'+str(s/'include'),str(r/'selected.c'),str(lib),'/Fo'+str(t/'selected.obj'),'/Fe:'+str(exe)]
 else:args=[cc,'-O2','-std=c11','-I',s,'-I',s/'include',r/'selected.c',lib,'-lm','-o',exe]
 run(args,'compile-selected');run([exe],'selected')
 lines=(out/'selected.log').read_text().splitlines();assert lines[-1]=='12288 raw iterator comparisons' and len(lines)==2
 counts=[int(x.split()[0]) for x in lines]
 if conf=='adapter':
  case=(s/'tests/unit/x86_scan_adapter.c').read_text().replace('../../arch/','arch/').replace('cs_disasm_iter(','X86_disasmIterScan32(')
  k='CHECK(X86_setScanAdapter(handle, CS_MODE_32, scan, &state));';assert case.count(k)==1
  case=case.replace(k,k+'''
    {
        static const uint8_t vex[] = {0xc5,0xfd,0x6f,0xc1};
        unsigned calls[2]; uint32_t ids[2];
        for (unsigned i=0;i<2;++i) {
            const uint8_t *p=vex; size_t left=sizeof(vex); uint64_t pc=0;
            state.result=(X86_INS_NOP << 8) | sizeof(vex);
            state.calls=0;
            CHECK((i?X86_disasmIterScan32:cs_disasm_iter)(handle,&p,&left,&pc,insn));
            CHECK(!left && pc==sizeof(vex));
            calls[i]=state.calls;ids[i]=insn->id;
        }
        CHECK(ids[0]==ids[1] && calls[0]==calls[1]);state.calls=0;
    }''')
  (t/'adapter.c').write_text(case);run([cc,'-O2','-std=c11','-I',s,'-I',s/'include',t/'adapter.c',lib,'-lm','-o',t/'adapter'],'compile-adapter');run([t/'adapter'],'adapter')
 write('verified',dict(tree=m['tree'],host=os.environ['CONFIG_NAME'],profile=conf,compiler=cc,tests=tests,foreign=counts[0],states=counts[1],callback=(conf=='adapter')))
finally:
 size=sum(v.stat().st_size for v in t.rglob('*')if v.is_file()and not v.is_symlink());shutil.rmtree(t);write('cleanup',dict(bytes=size,removed=not t.exists()))
