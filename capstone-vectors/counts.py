"""Count open and closed canonical printer calls in separate PowerPC-only libraries."""
from pathlib import Path
import hashlib,json,subprocess as sp
def trace(base,w,r,samples,maps):
    def cmd(*args):sp.run(args,check=True)
    get=lambda *args:sp.check_output(args,text=True)
    s=w/'ppc-counter-source';b=w/'ppc-counter-build'
    cmd('git','clone','-q','--shared','--no-checkout',base,s)
    images={}
    for tag in ('base','candidate'):
        cmd('git','-C',s,'checkout','-q','-f','--detach',maps['base']['commit'])
        if tag=='candidate':cmd('git','-C',s,'apply','--index',r/'candidate.patch')
        assert get('git','-C',s,'write-tree').strip()==maps['base' if tag=='base' else 'prefix']['tree']
        f=s/'arch/PowerPC/PPCGenAsmWriter.inc';v=f.read_text()
        k='static void printInstruction(MCInst *MI, uint64_t Address, SStream *O) {'
        assert v.count(k)==1
        f.write_text(v.replace(k,'''static uint64_t canonical_counts[2];
__attribute__((visibility("default"))) void ppc_canonical_counts(uint64_t result[2])
{
    result[0]=canonical_counts[0];
    result[1]=canonical_counts[1];
}
'''+k+'\n  ++canonical_counts[!!O->is_closed];'))
        cmd('cmake','-S',s,'-B',b,'-G','Ninja','-DCMAKE_BUILD_TYPE=Release','-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF','-DCAPSTONE_PPC_SUPPORT=ON','-DCAPSTONE_BUILD_SHARED_LIBS=ON','-DCAPSTONE_BUILD_STATIC_LIBS=OFF','-DCAPSTONE_BUILD_CSTEST=OFF','-DCAPSTONE_BUILD_CSTOOL=OFF')
        cmd('cmake','--build',b,'--target','capstone_shared','--parallel','4')
        src=(b/'libcapstone.so').resolve();dest=w/('count-'+tag+'.so');dest.write_bytes(src.read_bytes())
        images[tag]=hashlib.sha256(dest.read_bytes()).hexdigest()
    v=(r/'real-ppc.cpp').read_text();a=v.index('  std::cout<<ok')
    (w/'count.cpp').write_text(v[:a]+'''  uint64_t left[2],right[2];
  using Counts=void(*)(uint64_t *);
  auto get_a=(Counts)dlsym(original.library,"ppc_canonical_counts");
  auto get_b=(Counts)dlsym(trial.library,"ppc_canonical_counts");
  if(!get_a||!get_b)return 21;
  get_a(left);get_b(right);
  std::cout<<ok<<" "<<bad<<" "<<aliases<<" "<<unknown<<" "<<boundaries<<" "<<left[0]<<" "<<left[1]<<" "<<right[0]<<" "<<right[1]<<"\\n";
}
''')
    cmd('clang++','-std=c++17','-O2','-I',r,'-I',s/'include',w/'count.cpp','-ldl','-o',w/'count')
    result={}
    for name in samples:
        rows=[]
        for mode in range(4):
            data=list(map(int,get(w/'count',w/'count-base.so',w/'count-candidate.so',w/(name+'.text'),str(mode)).split()))
            assert len(data)==9 and data[5]==data[7]
            if mode==1:
                assert data[6]>0 and data[8]==0 and data[6]==data[2],(name,mode,data)
            else:assert data[6]==data[8],(name,mode,data)
            rows.append(data)
        result[name]=rows
    return dict(programs=result,images=images)
