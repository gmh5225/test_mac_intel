from pathlib import Path
import sys
import shlex
import subprocess as sp
r=Path(__file__).resolve().parent
w=Path(sys.argv[1])
b=Path(sys.argv[2])
out=['#include "Mapping.h"','#include <stdio.h>','#include <string.h>']
entries=[]
for folder, prefix, id in [('AArch64','AArch64','AARCH64'),('Mips','Mips','MIPS')]:
    d=w/"arch"/folder
    source=(d/(prefix+'Mapping.c')).read_text()
    body=source.split("static const name_map insn_alias_mnem_map[] = {",1)[1].split("};",1)[0]
    inc=prefix+'GenCSAliasMnemMap.inc'
    body=body.replace('#include "'+inc+'"',(d/inc).read_text())
    out.extend([f'static const name_map names_{id}[] = {{',body,'};',
                f'#define alias_group_indices grouped_{id}',f'#define alias_group_offsets offsets_{id}', f'#include "arch/{folder}/{prefix}GenAliasGroups.inc"','#undef alias_group_indices','#undef alias_group_offsets'])
    entries.append(f'{{ CS_ARCH_{id}, names_{id}, COUNT(names_{id}),grouped_{id}, offsets_{id} }}')
out.extend(['#define COUNT(a) (sizeof(a)/sizeof(a[0]))',
            'static const struct fixture { cs_arch arch; const name_map *names; size_t rows; const uint16_t *grouped; const uint16_t *offsets; } fixtures[] = {',
            ',\n'.join(entries),'};'])
out.append(r'''
static unsigned long long checks;
static int check(const struct fixture *f, MCInst *mi, SStream *ss) {
    mi->flat_insn->alias_id = 0xbadcafe;
    map_set_alias_id(mi, ss, f->names, (int)f->rows);
    uint64_t expected = mi->flat_insn->alias_id;
    mi->flat_insn->alias_id = 0xbadcafe;
    map_set_alias_id_grouped(mi, ss, f->names, f->grouped, f->offsets);
    ++checks;
    if (expected == mi->flat_insn->alias_id) return 1;
    fprintf(stderr, "arch %u input %s expected %llu got %llu\n", (unsigned)f->arch, ss->buffer,
            (unsigned long long)expected,(unsigned long long)mi->flat_insn->alias_id);
    return 0;
}
int main(void) {
    MCInst mi = {0};
    cs_struct handle = {0};
    cs_insn flat = {0};
    SStream stream = {0};
    mi.flat_insn = &flat;
    mi.csh = &handle;
    stream.index = 77;
    for (unsigned f = 0; f < COUNT(fixtures); ++f) {
        const struct fixture *input = &fixtures[f];
        handle.arch = input->arch;
        mi.isAliasInstr = false;
        if (!check(input, &mi, &stream)) return 1;
        mi.isAliasInstr = true;
        for (unsigned i = 0; i + 1 < input->rows; ++i) {
            const char *name = input->names[i].name;
            size_t length = strlen(name);
            char *start = stream.buffer + 2;
            stream.buffer[0] = ' ';
            stream.buffer[1] = '\t';
            for (size_t j = 0; j <= length; ++j) {
                for (unsigned c = 0; c < 256; ++c) {
                    strcpy(start,name);
                    start[length + 1] = 0;
                    start[j] = (char)c;
                    if (!check(input, &mi, &stream)) return 1;
                }
            }
            for (unsigned n = 0; n < 18; ++n) {
                memset(start, 'x', n);
                strcpy(start + n, name);
                strcat(start,"\t r2");
                if (!check(input, &mi, &stream)) return 1;
            }
        }
    }
    printf("%llu original/grouped alias decisions matched across AArch64 and MIPS maps\n", checks);
}
''')
src=r/"alias_oracle.c"
src.write_text("\n".join(out))
line=next(l for l in sp.check_output(['ninja','-C',b,'-t','commands','capstone_static'],text=True).splitlines() if ' -c ' in l and '/Mapping.c' in l)
flags=[v for v in shlex.split(line) if v.startswith('-D') or v.startswith('-I')]
cmd=['clang','-O2',*flags,'-I',w,'-I',w/'include',src,b/'libcapstone.a','-o',b/'alias-oracle']
sp.run(cmd,check=True)
with (r/'direct-alias-check.log').open('w') as output:
    sp.run([b/'alias-oracle'],stdout=output,check=True)
print((r/'direct-alias-check.log').read_text())
