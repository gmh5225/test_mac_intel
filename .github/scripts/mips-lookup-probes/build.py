"""Build the unchanged driver around the native MIPS parser from each real fork commit."""
from pathlib import Path
import hashlib,json,os,shutil,subprocess

root=Path.cwd()
fork=root/'source'
work=Path(os.environ['RUNNER_TEMP'])/'mips-probes'
work.mkdir()
out=root/'lookup-evidence';out.mkdir()
archive_name='neverd-llvm-linux-x86_64.tar.xz'
r13='24ced447e1718432292dc9d54b6eb229323409d1'
r14='6c769154fbe9db2fe9e2e2dc1b04bebfe64e1312'
revisions={'rebuilt':r14,'binary':'7efde556745738c7c1384018785d07e44188e4ec','early':'ab9560087ab2dbe240950c01b8a63aa7301495fa',
           'set':'bb5dad8aa063621f925898aacf7d265b6efe65fe'}
def run(args,cwd=None):
    subprocess.run(args,cwd=cwd,check=True)
def check(args,cwd=None):
    return subprocess.check_output(args,cwd=cwd,text=True).strip()
def sha(path):
    with path.open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
def stage_driver(label,sdk,parser=None):
    dest=work/('driver-'+label)
    args=['cmake','-G','Ninja','-S',Path(__file__).resolve().parent,'-B',dest,'-DCMAKE_BUILD_TYPE=Release',
          '-DCMAKE_C_COMPILER=clang-18','-DCMAKE_CXX_COMPILER=clang++-18','-DLLVM_DIR='+str(sdk/'lib/cmake/llvm'),
          '-DMC_SOURCE='+str(fork/'llvm/tools/llvm-mc')]
    if parser:args.append('-DMIPS_PARSER_ARCHIVE='+str(parser))
    run(args)
    linked=check(['ninja','-C',dest,'-t','commands','llvm-mc']).splitlines()[-1]
    selected=parser or (sdk/'lib/libLLVMMipsAsmParser.a')
    assert str(selected) in linked,(label,linked)
    if parser:assert str(sdk/'lib/libLLVMMipsAsmParser.a') not in linked,linked
    (out/(label+'-link.txt')).write_text(linked+'\n')
    run(['cmake','--build',dest,'--parallel','2','--target','llvm-mc'])
    exe=dest/'llvm-mc'
    deps=check(['ldd',exe]);assert 'libLLVM' not in deps and 'not found' not in deps
    return exe
sdks={};bins={};provenance={}
for label,rev,expected in [('r13',r13,'9c48f639fa51c5de8d1482ea9e23409d215fc6d6022873cff5899154862c8672'),
                          ('r14',r14,'8bdcf7289ada160858c35ccb6dbf848c46c75161063c65b5653954b3e4d4d2bd')]:
    area=work/label;area.mkdir()
    pkg=area/archive_name
    url='https://github.com/NeverSight/llvm-project/releases/download/neverd-llvm-v23.0.0-'+label+'/'+archive_name
    run(['curl','--fail','--location','--retry','3','--silent','--show-error','--output',pkg,url])
    assert sha(pkg)==expected
    run(['tar','-xJf',pkg,'-C',area]);sdk=area/'neverd-llvm-linux-x86_64';sdks[label]=sdk
    assert 'llvm_commit: '+rev in (sdk/'BUILDINFO.txt').read_text().splitlines()
    assert check(['git','rev-parse','HEAD:llvm/tools/llvm-mc'],fork)=='fe2dd646d45346aaf30951c0d3f3741bc9e39680'
    bins[label]=stage_driver(label,sdk)
    provenance[label]={'source':rev,'sdk':expected,'parser_sha256':sha(sdk/'lib/libLLVMMipsAsmParser.a'),'driver':sha(bins[label])}
    pkg.unlink()
run(['git','fetch','--no-tags','--depth=1','--filter=blob:none','origin',*set(revisions.values())],fork)
build=work/'parser'
for label,sha1 in revisions.items():
    run(['git','checkout','--detach',sha1],fork)
    assert check(['git','rev-parse','HEAD'],fork)==sha1
    paths=check(['git','diff','--name-only',r14,sha1],fork).splitlines()
    assert paths==([] if label=='rebuilt' else ['llvm/lib/Target/Mips/AsmParser/MipsAsmParser.cpp']),paths
    if not build.exists():
        opts=['-DCMAKE_BUILD_TYPE=Release','-DCMAKE_C_COMPILER=clang-18','-DCMAKE_CXX_COMPILER=clang++-18',
              '-DLLVM_TARGETS_TO_BUILD=X86;ARM;AArch64;Mips','-DLLVM_ENABLE_PROJECTS=','-DLLVM_ENABLE_RTTI=ON',
              '-DLLVM_ENABLE_ASSERTIONS=OFF','-DBUILD_SHARED_LIBS=OFF','-DLLVM_ENABLE_PIC=ON','-DLLVM_USE_LINKER=lld',
              '-DLLVM_ENABLE_ZLIB=OFF','-DLLVM_ENABLE_ZSTD=OFF','-DLLVM_ENABLE_LIBXML2=OFF','-DLLVM_INCLUDE_TESTS=OFF',
              '-DLLVM_INCLUDE_BENCHMARKS=OFF','-DLLVM_INCLUDE_EXAMPLES=OFF','-DLLVM_INCLUDE_TOOLS=OFF',
              '-DLLVM_ENABLE_TERMINFO=OFF','-DLLVM_ENABLE_LIBEDIT=OFF','-DLLVM_ENABLE_CURL=OFF','-DLLVM_ENABLE_HTTPLIB=OFF']
        run(['cmake','-S',fork/'llvm','-B',build,'-G','Ninja',*opts])
    run(['cmake','--build',build,'--parallel','4','--target','LLVMMipsAsmParser'])
    source_lib=build/'lib/libLLVMMipsAsmParser.a'
    kept=work/('parser-'+label+'.a');shutil.copy2(source_lib,kept)
    bins[label]=stage_driver(label,sdks['r14'],kept)
    provenance[label]={'source':sha1,'recipient_sdk':provenance['r14']['sdk'],'parser_sha256':sha(kept),
                       'driver':sha(bins[label]),'source_blob':check(['git','rev-parse','HEAD:llvm/lib/Target/Mips/AsmParser/MipsAsmParser.cpp'],fork)}
(out/'drivers.json').write_text(json.dumps(provenance,indent=2)+'\n')
(work/'paths.json').write_text(json.dumps({k:str(v) for k,v in bins.items()},indent=2)+'\n')
