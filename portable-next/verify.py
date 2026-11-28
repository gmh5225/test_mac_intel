from pathlib import Path
import collections,hashlib,json,os,shutil,subprocess as sp,tempfile
r=Path(__file__).resolve().parent;e=r.parent/'evidence';e.mkdir(exist_ok=True);s=r.parent/'source'
q=json.loads((r/'source.json').read_bytes());profile=os.environ['SCAN_PROFILE']
git=lambda *a:sp.check_output(['git','-C',s,*a],text=True).strip()
def run(*a):sp.run(a,check=True)
def save(name,v):(e/(name+'.json')).write_text(json.dumps(v,indent=2)+'\n')
def sha(b):return hashlib.sha256(b).hexdigest()
w=Path(tempfile.mkdtemp());b=w/'build';data=(r/'cases.tsv').read_bytes();cases=len(data.splitlines());expected=json.loads((r/'expected.json').read_bytes());assert cases==len(expected)==3584
try:
 assert git('rev-parse','HEAD')==q['parent']
 blob=sp.check_output(['git','-C',r.parent,'cat-file','blob','HEAD:portable-next/candidate.patch']);assert sha(blob)==q['sha256']
 worktree=(r/'candidate.patch').read_bytes()
 assert worktree.replace(b'\r\n',b'\n')==blob
 save('patch-input',dict(blob_sha256=sha(blob),checkout_sha256=sha(worktree),crlf_checkout=blob!=worktree,parent=git('rev-parse','HEAD')))
 arches=['X86','ARM','AARCH64','MIPS','PPC','RISCV']if profile not in('reduced','diet')else['X86','PPC']
 flags=['-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',*['-DCAPSTONE_'+a+'_SUPPORT=ON'for a in arches],'-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_BUILD_MACOS_THIN=ON','-DCAPSTONE_BUILD_CSTEST=ON','-DCAPSTONE_BUILD_CSTOOL=OFF','-DCAPSTONE_BUILD_LEGACY_TESTS=OFF','-DCAPSTONE_BUILD_STATIC_LIBS=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON']
 flags+=dict(gcc=['-DCMAKE_C_COMPILER=gcc','-DCMAKE_CXX_COMPILER=g++'],clang=['-DCMAKE_C_COMPILER=clang','-DCMAKE_CXX_COMPILER=clang++'],full=[],noatt=['-DCAPSTONE_X86_ATT_DISABLE=ON'],diet=['-DCAPSTONE_BUILD_DIET=ON'],reduced=['-DCAPSTONE_X86_REDUCE=ON'])[profile]
 run('cmake','-G','Ninja','-S',s,'-B',b,*flags);units=['x86_reg_access','x86_mapping_counts','x86_buffer_bounds','text_option']
 if profile not in('diet','reduced'):units+=['x86_simple_output','x86_evex_detail','x86_vex_legacy_prefix']
 if len(arches)>2:units+=['arm_reg_access','aarch64_scan','mips_scan','riscv_reg_access']
 rows={};hashes={}
 for tag in ('base','fixed'):
  if tag=='fixed':
   patch=w/'candidate.patch';patch.write_bytes(sp.check_output(['git','-C',r.parent,'cat-file','blob','HEAD:portable-next/candidate.patch']));assert sha(patch.read_bytes())==q['sha256'];git('apply','--index',patch);assert git('write-tree')==q['tree']
  run(os.sys.executable,'-B',s/'suite/synctools/x86_mapping_counts.py','--check')
  run('cmake','--build',b,'--target','capstone_static','capstone_shared',*units,'--parallel','4')
  result=sp.run(['ctest','--test-dir',b,'--output-on-failure','--no-tests=error','-R','^unit_('+'|'.join(units)+')$'],text=True,capture_output=True);(e/(tag+'-ctest.txt')).write_text(result.stdout+result.stderr)
  if result.returncode:print(result.stdout+result.stderr,flush=True);result.check_returncode()
  form=(r/'access.c').read_text();src=w/'driver.c'
  nsyntax=1 if profile=='noatt'else 2
  if profile=='diet':
   src.write_bytes((r/'diet.c').read_bytes());nsyntax=1
  else:src.write_text(form.replace('a<2','a<'+str(nsyntax)))
  links={}
  for typ in ('static','shared'):
   win=os.name=='nt';exe=(b if win and typ=='shared'else w)/('check.exe'if win else 'check')
   if win:
    runtime='/MT' if 'CAPSTONE_BUILD_STATIC_MSVC_RUNTIME:BOOL=ON'in(b/'CMakeCache.txt').read_text() else '/MD'
    lib=b/('capstone_static.lib'if typ=='static'else'capstone.lib')
    run('cl','/nologo','/std:c11','/O2',runtime,'/I'+str(s/'include'),src,lib,'/Fo:'+str(w/'driver.obj'),'/Fe:'+str(exe))
   else:
    lib=b/('libcapstone.a'if typ=='static'else ('libcapstone.dylib'if os.sys.platform=='darwin'else 'libcapstone.so'))
    run('gcc' if profile=='gcc'else 'clang','-std=c11','-O2','-I',s/'include',src,lib,'-Wl,-rpath,'+str(b),'-o',exe)
   raw=sp.check_output([exe],input=data);rec=[list(map(int,line.split()))for line in raw.splitlines()]
   if profile=='diet':
    assert len(rec)==cases and all(row[0]==i and row[-1]==1 for i,row in enumerate(rec));metadata=sha(raw);bad=duplicate=0
   else:
    assert len(rec)==cases*2*nsyntax
    signature=hashlib.sha256();bad=duplicate=0
    for index,z in enumerate(rec):
     i,a,t,size,insn,ops,strings,rr,ww,dup=z
     assert (i,a,t)==(index//(2*nsyntax),(index//2)%nsyntax,index%2) and size>0 and insn>0
     signature.update((' '.join(map(str,z[:-1]))+'\n').encode())
     want=expected[i][:2]if t else expected[i][2:];bad+=([rr,ww]!=want);duplicate+=(dup>0)
    metadata=signature.hexdigest()
    if tag=='fixed':assert duplicate==0 and bad==rows['base'][typ]['incorrect'],(profile,typ,bad,duplicate)
    else:assert bad>0 and duplicate>0
   links[typ]=dict(metadata=metadata,all=sha(raw),attempts=len(rec),incorrect=bad,duplicate=duplicate,library=sha(lib.read_bytes()))
  assert links['static']['all']==links['shared']['all']
  rows[tag]=links;save('results',rows)
 for typ in links:assert rows['base'][typ]['metadata']==rows['fixed'][typ]['metadata']
 save('complete',dict(complete=True,source=q,profile=profile,units=units,rows=rows,architectures=arches))
finally:
 n=sum(f.stat().st_size for f in w.rglob('*')if f.is_file()and not f.is_symlink());shutil.rmtree(w);save('cleanup',dict(bytes=n,removed=not w.exists()))

