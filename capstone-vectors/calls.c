#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
struct edge { uintptr_t caller, callee; uint64_t calls; };
static struct edge table[1u<<15];
void __cyg_profile_func_enter(void *fn, void *ret)
{
    uintptr_t callee=(uintptr_t)fn, caller=(uintptr_t)ret;
    unsigned pos=(unsigned)((callee>>4)*2654435761u+(caller>>2)) & 32767;
    for(unsigned i=0;i<32768;i++,pos=(pos+1)&32767) {
        struct edge *e=table+pos;
        if (!e->callee) { e->callee=callee; e->caller=caller; }
        if (e->callee==callee && e->caller==caller) { ++e->calls; return; }
    }
    abort();
}
void __cyg_profile_func_exit(void *fn,void *ret){(void)fn;(void)ret;}
__attribute__((destructor)) static void finish(void)
{
    const char *path=getenv("COUNT_OUTPUT"); if(!path)return;
    FILE *out=fopen(path,"w"); if(!out)abort();
    for(unsigned i=0;i<32768;i++)if(table[i].callee)
        fprintf(out,"%" PRIxPTR " %" PRIxPTR " %" PRIu64 "\n",table[i].caller,table[i].callee,table[i].calls);
    if(fclose(out))abort();
}

