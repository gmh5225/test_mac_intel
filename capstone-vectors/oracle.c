#include "cs_priv.h"
#include "arch/X86/X86SimpleOutput.h"
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>

static unsigned checks;
static void check(int32_t n) {
    const uint32_t magnitude=n<0?0u-(uint32_t)n:(uint32_t)n;
    char expected[80],actual[80],text[40]={0};
    if(n)snprintf(text,sizeof(text),magnitude<=9?" %c %" PRIu32:" %c 0x%" PRIx32,n<0?'-':'+',magnitude);
    memset(expected,0x5a,sizeof(expected));memset(actual,0x5a,sizeof(actual));
    const size_t len=strlen(text);
    char *out=actual+11;
    memcpy(expected+11,text,len);
    if(X86_writeDisplacement(out,n)!=out+len || memcmp(expected,actual,sizeof(actual))) {
        fprintf(stderr,"incorrect signed displacement %" PRId32 "\n",n);abort();
    }
    ++checks;
}
int main(void) {
    for(int i=-65536;i<=65536;++i)check(i);
    check(INT32_MIN);check(INT32_MAX);
    for(unsigned shift=0;shift<32;shift+=4) for(unsigned nibble=1;nibble<=15;++nibble) for(int d=-1;d<=1;++d) {
        const uint32_t u=((uint32_t)nibble<<shift)+(uint32_t)d;
        check((int32_t)u);check((int32_t)(0u-u));
    }
    uint32_t v=UINT32_C(0xa67b013f);
    for(unsigned i=0;i<200000;++i){v^=v<<13;v^=v>>17;v^=v<<5;check((int32_t)v);}
    printf("%u exact byte ranges, spelling and returned end pointers\n",checks);
    return 0;
}
