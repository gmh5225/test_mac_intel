import hashlib,json,os,struct,subprocess
from pathlib import Path
root=Path('pe-header-evidence');root.mkdir()
clang=os.environ['SOURCE_CLANG']
flags=['-O0','-fno-omit-frame-pointer','-funwind-tables','--target=x86_64-pc-windows-msvc']
def run(c,label):
 r=subprocess.run([str(v) for v in c],capture_output=True,text=True,timeout=60)
 row={'command':[str(v) for v in c],'returncode':r.returncode,'stdout':r.stdout,'stderr':r.stderr}
 (root/(label+'.json')).write_text(json.dumps(row,indent=2)+'\n')
 if r.returncode:raise RuntimeError(label+': '+r.stderr)
 return r
objects=[]
for i in range(32):
 p=root/f'h{i}.obj';run([clang,*flags,'-c','examples/source-patch/header_section.c',f'-DEXAMPLE_SECTION=".demo{i}"',f'-DEXAMPLE_SYMBOL=demo_{i}','-o',p],f'object-{i}');objects.append(p)
rows=[]
run([clang,*flags,'-###','examples/source-patch/original.c','-o',root/'trace.exe'],'driver-trace')
for n in (0,7,8,9,32):
 p=root/f'capacity-{n}.exe'
 run([clang,*flags,'examples/source-patch/original.c',*objects[:n],'-o',p],f'link-{n}')
 b=p.read_bytes();pe=struct.unpack_from('<I',b,60)[0];count=struct.unpack_from('<H',b,pe+6)[0];optional=struct.unpack_from('<H',b,pe+20)[0];headers=struct.unpack_from('<I',b,pe+84)[0];end=pe+24+optional+count*40
 result=run([p.resolve(),'7'],f'execute-{n}');assert result.stdout.strip()=='8'
 row={'extra_sections':n,'sections':count,'header_end':end,'header_bytes':headers,'free_header_bytes':headers-end,'sha256':hashlib.sha256(b).hexdigest()};rows.append(row);print(json.dumps(row),flush=True)
record={'scope':'native header-capacity controls and original-process execution only; no patch or SDK acceptance','source_commit':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),'compiler_version':run([clang,'--version'],'compiler').stdout,'observations':rows}
assert 0<=next(r for r in rows if r['extra_sections']==7)['free_header_bytes']<3*40
(root/'result.json').write_text(json.dumps(record,indent=2)+'\n')
