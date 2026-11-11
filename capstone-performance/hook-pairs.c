#include "cs_priv.h"
#include "SStream.h"
#include <stdio.h>
#include <stdlib.h>
extern unsigned direct_count, heap_count;
extern int previous_direct(void);
__declspec(noinline) static cs_malloc_t expression_malloc(void) { return malloc; }
__declspec(noinline) static cs_free_t expression_free(void) { return free; }
static void *CAPSTONE_API custom_malloc(size_t n){ return malloc(n); }
static void CAPSTONE_API custom_free(void *p){ free(p); }
static void probe(const char *name, cs_malloc_t m, cs_free_t f) {
    cs_opt_mem hooks={m,calloc,realloc,f,vsnprintf};
    if(cs_option(0,CS_OPT_MEM,(size_t)&hooks))exit(2);
    direct_count=heap_count=0;
    SStream stream; SStream_Init(&stream); SStream_concat0_substr(&stream,"normal",3);
    if(strcmp(stream.buffer,"nor"))exit(1);
    printf("%s old %d direct %u heap %u\n",name,previous_direct(),direct_count,heap_count);
}
int main(void) {
    cs_malloc_t m=cs_mem_malloc;cs_free_t f=cs_mem_free;
    probe("built-in",m,f);
    probe("explicit CRT",expression_malloc(),expression_free());
    probe("custom malloc",custom_malloc,f);
    probe("custom free",m,custom_free);
    probe("restored built-in",m,f);
    return 0;
}
