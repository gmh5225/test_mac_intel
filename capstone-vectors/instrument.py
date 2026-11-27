"""Select both unmodified handler bodies inside one executable; count entries only in separate runs."""
def handler(text,name):
    start=text.index('bool '+name+'(')
    end=text.index('\n}',start)+2
    return text[start:end]
def instrument(before,after):
    old_name='X86_writeVexRegisterImmediate'
    new_name='X86_writeVex3FallbackOutput'
    old=handler(before,old_name);new=handler(after,new_name)
    head=new[:new.index('\n{')]
    decl='static __attribute__((noinline,aligned(64))) '
    rows=[decl+old.replace(old_name,'original_c4',1),decl+new.replace(new_name,'extended_c4',1)]
    rows.append(r'''
#include <stdio.h>
#include <stdlib.h>
static __typeof__(&original_c4) volatile selected_c4;
static unsigned long long entries[2];
static bool count_entries;
__attribute__((constructor)) static void setup_c4(void)
{
    const char *stage = getenv("ND_VEX_STAGE");
    count_entries = getenv("ND_VEX_COUNT") != NULL;
    selected_c4 = stage && *stage == 'b' ? extended_c4 : original_c4;
}
__attribute__((destructor)) static void report_c4(void)
{
    if (count_entries)
        fprintf(stderr, "C4 %llu %llu %p %p %p\n", entries[0], entries[1],
                (void *)original_c4, (void *)extended_c4, (void *)selected_c4);
}
''')
    rows.append(head+r'''
{
    if (count_entries)
        ++entries[wide];
    return selected_c4(handle, code, size, insn, insn_size, regs, wide);
}''')
    return after.replace(new,'\n\n'.join(rows))
