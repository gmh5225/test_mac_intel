from pathlib import Path
import hashlib, json, os, shlex, subprocess as sp

def link(w,r,base,db,lib,ad,flags,syslibs,run,save):
    directory=base/'arch/X86'
    def extra(src,model,target,defines=()):
        row,=[x for x in db if Path(x['file']).name==model]
        args=shlex.split(row['command']);source=str(row['file']);assert args.count(source)==1
        args[args.index(source)]=str(src)
        args[args.index('-o')+1]=str(target)
        args.extend(['-iquote',str(directory),*['-D'+n for n in defines]])
        run(args,'compile-'+target.stem,cwd=row['directory'])
    funcs=[];symbol=lambda label:'bench_'+label
    for k in ('direct','duplicate','old','count'):
        path=r/('direct-entry.c' if k in ('direct','duplicate') else 'old-entry.c')
        args=['X86_decodeOutputMiss64='+symbol(k)]
        if k in ('old','count'):args.append('X86_decodeVexMemoryOrFull='+symbol(k+'_writer'))
        obj=w/(k+'-entry.o');extra(path,'X86VectorFallback64.c',obj,args);funcs.append(obj)
    writer=(r/'old-writer.c').read_text()
    a='\tif ((code[0] & 0xfe) == 0xc4) {';b='\t\t\t\t       x86_simple_registers[3]))\n\t\t\treturn true;'
    assert writer.count(a)==writer.count(b)==1
    counted=writer.replace(a,'\textern unsigned long long bench_calls[4];\n\t++bench_calls[1];\n'+a+'\n\t\t++bench_calls[2];')
    counted=counted.replace(b,b.replace('))\n', ')) {\n\t\t\t++bench_calls[3];\n')+'\n\t\t}')
    (w/'count-writer.c').write_text(counted)
    for k,src in [('old',r/'old-writer.c'),('count',w/'count-writer.c')]:
        obj=w/(k+'-writer.o');extra(src,'X86VexBaseMemory.c',obj,['X86_decodeVexMemoryOrFull='+symbol(k+'_writer')]);funcs.append(obj)
    driver=w/'choice.c'
    driver.write_text('''#include "../../cs_priv.h"
#include "X86OutputOptions.h"
#include <stdio.h>
#include <stdlib.h>
typedef __typeof__(X86_decodeOutputMiss64) miss_fn;
extern miss_fn bench_direct, bench_duplicate, bench_old, bench_count, __real_X86_decodeOutputMiss64;
unsigned long long bench_calls[4];
static miss_fn *route;
static void record(void) {
    FILE *out = fopen(getenv("CAPSTONE_ROUTE_RECEIPT"), "w");
    if (!out) abort();
    fprintf(out, "%llu %llu %llu %llu\\n", bench_calls[0], bench_calls[1], bench_calls[2], bench_calls[3]);
    if (fclose(out)) abort();
}
static CS_PRESERVE_MOST bool count_entry(cs_struct *h, const uint8_t *c, size_t n, cs_insn *i, uint16_t *l, bool b) {
    ++bench_calls[0];
    return bench_count(h,c,n,i,l,b);
}
__attribute__((constructor)) static void init_route(void) {
    const char *v = getenv("CAPSTONE_BENCH_ROUTE");
    switch (v ? *v : 'g') {
    case 'a': route = bench_direct; break;
    case 'b': route = bench_duplicate; break;
    case 't': route = bench_old; break;
    case 'g': route = __real_X86_decodeOutputMiss64; break;
    case 'c': route = count_entry; if (atexit(record)) abort(); break;
    default: abort();
    }
}
CS_PRESERVE_MOST bool __wrap_X86_decodeOutputMiss64(cs_struct *h, const uint8_t *c, size_t n, cs_insn *i, uint16_t *l, bool b) {
    return route(h,c,n,i,l,b);
}
''')
    obj=w/'choice.o';extra(driver,'X86VectorFallback64.c',obj);funcs.append(obj)
    exe=w/'runner-switch'
    run(['clang++',w/'driver.o',*flags,*funcs,'-Wl,--wrap=X86_decodeOutputMiss64',lib,ad/'target/release/libiced_compare.a',*syslibs,'-o',exe],'link-switch')
    names={'bench_direct','bench_duplicate','bench_old','bench_count','__wrap_X86_decodeOutputMiss64','X86_decodeOutputMiss64','X86_decodeVexMemoryOrFull'}
    symbols={line.split()[2]:line.split()[0]for line in sp.check_output(['nm','-n',exe],text=True).splitlines() if len(line.split())==3 and line.split()[2] in names}
    assert symbols.keys()==names and len(set(symbols.values()))==len(names)
    save('route-symbols.json',symbols)
    return exe
