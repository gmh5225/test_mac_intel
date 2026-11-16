from pathlib import Path
import hashlib
import json
import os
import platform
import shutil
import subprocess as sp
import tempfile

r = Path(__file__).resolve().parent
p = r.parent
evidence = p / 'evidence'
evidence.mkdir()
base = p / 'source'
meta = json.loads((r / 'candidate.json').read_text())


def save(name, data):
    (evidence / (name + '.json')).write_text(json.dumps(data, indent=2) + '\n')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(args, label, cwd=None):
    with (evidence / (label + '.log')).open('wb') as out:
        sp.run(list(map(str, args)), cwd=cwd, stdout=out, stderr=sp.STDOUT, check=True)


w = Path(tempfile.mkdtemp(prefix='capstone-clang14-vectors-boundary-'))
try:
    assert os.environ['CC'] == 'clang'
    assert sp.check_output(['git', '-C', base, 'rev-parse', 'HEAD'], text=True).strip() == meta['parent']
    save('environment', dict(platform=platform.platform(), machine=platform.machine(),
         cpu=Path('/proc/cpuinfo').read_text(), compiler=sp.check_output(['clang', '--version'], text=True),
         cxx=sp.check_output(['clang++', '--version'], text=True),
         cmake=sp.check_output(['cmake', '--version'], text=True),
         linker=sp.check_output(['ld', '--version'], text=True),
         debugger=sp.check_output(['gdb', '--version'], text=True),
         original_failure_run=43936130678, original_revision='89768ab7e3d57e4bb59f910eafaebbd24ae7b732',
         original_signal=11, rebuilt_reproducer=True))
    import deb
    case = next(x for x in deb.prepare(w) if x[0] == 'libjpeg62-turbo-amd64')
    name, bits, data, spans, provenance = case
    intervals = w / 'intervals.tsv'
    intervals.write_text(''.join('%d %d %d\n' % item for item in spans))
    save('input', dict(name=name, bits=bits, provenance=provenance,
         text_sha256=sha(data), intervals_sha256=sha(intervals), intervals=len(spans)))
    tree, build = w / 'source', w / 'build'
    run(['git', 'clone', '-q', '--shared', '--no-checkout', base, tree], 'clone')
    run(['git', 'checkout', '-q', '--detach', meta['parent']], 'checkout', tree)
    options = ['-G', 'Ninja', '-DCMAKE_BUILD_TYPE=Release', '-DCMAKE_C_COMPILER=clang',
               '-DCAPSTONE_ARCHITECTURE_DEFAULT=OFF',
               *['-DCAPSTONE_' + arch + '_SUPPORT=ON' for arch in ['X86', 'ARM', 'AARCH64', 'MIPS']],
               '-DCMAKE_C_FLAGS_RELEASE=-O3 -DNDEBUG -fomit-frame-pointer -Wno-error=incompatible-pointer-types-discards-qualifiers',
               '-DCAPSTONE_BUILD_MACOS_THIN=ON', '-DCAPSTONE_BUILD_SHARED_LIBS=OFF',
               '-DCAPSTONE_BUILD_STATIC_LIBS=ON', '-DCAPSTONE_BUILD_LEGACY_TESTS=OFF',
               '-DCAPSTONE_BUILD_CSTOOL=OFF']
    run(['cmake', '-S', tree, '-B', build, *options], 'configure')
    observations = []
    for label in ['baseline', 'cdecl']:
        if label == 'cdecl':
            header = tree / 'cs_priv.h'
            code = header.read_text()
            marker = '#if __has_attribute(preserve_most)'
            assert code.count(marker) == 1
            header.write_text(code.replace(marker, '#if 0 /* diagnostic: use the default private calling convention */'))
            (evidence / 'cdecl.patch').write_bytes(sp.check_output(['git', 'diff'], cwd=tree))
        run(['cmake', '--build', build, '--target', 'capstone_static', '--parallel', '4'], 'build-' + label)
        executable = w / ('vectors-' + label)
        command = ['clang++', '-O2', '-I', base / 'include', r / 'vectors.cpp', build / 'libcapstone.a', '-o', executable]
        run(command, 'link-' + label)
        guarded = w / 'guarded.cpp'
        original = (r / 'vectors.cpp').read_text()
        marker = '   if(!cs_disasm_iter(h,&cursor,&n,&address,insn)){++cursor;--n;++address;continue;}'
        assert original.count(marker) == 1
        guard = r"""   volatile size_t before_n=n;
   volatile uintptr_t before_cursor=reinterpret_cast<uintptr_t>(cursor);
   volatile uint64_t before_ip=address;
   const bool ok=cs_disasm_iter(h,&cursor,&n,&address,insn);
   const bool bad=ok ? (!insn->size || insn->size>before_n || n!=before_n-insn->size ||
      reinterpret_cast<uintptr_t>(cursor)!=before_cursor+insn->size || address!=before_ip+insn->size) :
      (n!=before_n || reinterpret_cast<uintptr_t>(cursor)!=before_cursor || address!=before_ip);
   if(bad) {
    std::fprintf(stderr,"violation ok=%d start=%zu span_length=%zu old_remaining=%zu new_remaining=%zu old_cursor=%llx new_cursor=%llx old_ip=%llx new_ip=%llx insn_size=%u id=%u\n",ok,start,size_t(before_n),size_t(before_n),n,(unsigned long long)before_cursor,(unsigned long long)reinterpret_cast<uintptr_t>(cursor),(unsigned long long)before_ip,(unsigned long long)address,unsigned(insn->size),insn->id);
    const auto pos=before_cursor-reinterpret_cast<uintptr_t>(bytes.data());
    if(pos<bytes.size()) {
     std::fprintf(stderr,"input:");
     for(size_t i=0;i<15 && i<before_n && i<bytes.size()-pos;++i)std::fprintf(stderr," %02x",unsigned(bytes[pos+i]));
     std::fprintf(stderr,"\n");
    }
    return 77;
   }
   if(!ok){++cursor;--n;++address;continue;}"""
        instrumented = original.replace(marker, guard)
        instrumented = instrumented.replace(' cs_insn *insn=cs_malloc(h);', ' if(std::getenv("CAPSTONE_PROBE_NO_TEXT"))cs_option(h,CS_OPT_TEXT,CS_OPT_OFF);\n cs_insn *insn=cs_malloc(h);')
        guarded.write_text(instrumented)
        (evidence / 'guarded.cpp').write_text(instrumented)
        guarded_exe=w/('guarded-'+label)
        run(['clang++','-O2','-I',base/'include',guarded,build/'libcapstone.a','-o',guarded_exe], 'link-guarded-'+label)
        (evidence / (label + '-symbols.txt')).write_bytes(sp.check_output(['nm', '-n', '-S', '--defined-only', executable]))
        for surface, target, no_text in [('original',executable,False),('guarded',guarded_exe,False),('guarded-no-text',guarded_exe,True)]:
            ident=label+'-'+surface
            arguments=[target,str(bits),data,intervals]
            env=dict(os.environ)
            if no_text:env['CAPSTONE_PROBE_NO_TEXT']='1'
            with (evidence / (ident + '-stdout.txt')).open('wb') as stdout, (evidence / (ident + '-stderr.txt')).open('wb') as stderr:
                result = sp.run(list(map(str, arguments)), stdout=stdout, stderr=stderr, timeout=120,env=env)
            observation = dict(label=label,surface=surface,no_text=no_text,returncode=result.returncode,binary_sha256=sha(target),
                               archive_sha256=sha(build/'libcapstone.a'),stdout_sha256=sha(evidence/(ident+'-stdout.txt')),
                               completed_lines=len((evidence/(ident+'-stdout.txt')).read_text().splitlines()))
            observations.append(observation)
            save('observations',observations)
            if result.returncode<0 and surface=='original':
                args=['gdb','-q','--batch','-ex','set pagination off','-ex','run','-ex','thread apply all bt full',
                      '-ex','info registers','-ex','x/20i $pc-32','-ex','info frame','--args',*arguments]
                with (evidence/('gdb-'+ident+'.log')).open('wb') as out:
                    debugger=sp.run(list(map(str,args)),stdout=out,stderr=sp.STDOUT,timeout=180)
                observation['debugger_returncode']=debugger.returncode
                save('observations',observations)
    save('complete', dict(success=True, diagnostic_only=True, cases=len(observations),
                          no_native_performance_claim=True))
finally:
    files = [path for path in w.rglob('*') if path.is_file()]
    amount = sum(path.stat().st_size for path in files)
    shutil.rmtree(w)
    save('cleanup', dict(bytes=amount, files=len(files), removed=not w.exists()))
