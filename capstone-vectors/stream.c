#include "cs_priv.h"
#include "arch/ARM/ARMMapping.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned behavior, calls, hash;
static int observe(char *out, size_t n, const char *fmt, va_list ap)
{
    va_list copy;
    unsigned count = !strcmp(fmt,"%s") ? 1 : !strcmp(fmt,"%s%s") ? 2 : 0;
    if (!count) abort();
    va_copy(copy,ap);
    hash=hash*33+(unsigned)n;
    for (unsigned i=0;i<count;++i) {
        const char *p=va_arg(copy,const char *);
        while (*p) hash=hash*33+(unsigned char)*p++;
        hash=hash*33+1;
    }
    va_end(copy);
    ++calls;
    if(behavior==2)return -1;
    if(behavior==3){if(n){memset(out,'t',n-1);out[n-1]=0;}return (int)n+3;}
    return vsnprintf(out,n,fmt,ap);
}
static void write_token(SStream *s,unsigned test,bool candidate)
{
    static const char *const chars[]={"]","#","[","{",":"};
    if(test<5) {
        if (candidate) ARM_printFormattedChar(s,chars[test]);
        else SStream_concat(s,"%s",chars[test]);
    } else if(test==5) {
        if (candidate) ARM_printMarkup(s,"<mem:");
        else SStream_concat(s,"%s",markup("<mem:"));
    } else {
        const char *tag=test==6?markup("<imm:"):"<imm:";
        if (candidate && TEST_PAIR) SStream_concat2(s,", ",tag);
        else SStream_concat(s,"%s%s",", ",tag);
    }
}
int main(void)
{
    unsigned count=0,callbacks=0;
    cs_vsnprintf_t standard=cs_vsnprintf;
    for(behavior=0;behavior<4;++behavior) {
        cs_vsnprintf=behavior?observe:standard;
        for(unsigned test=0;test<8;++test) for(unsigned state=0;state<16;++state)
         for(size_t idx=0;idx<SSTREAM_BUF_LEN;++idx) {
            SStream a,b;memset(&a,0xa5,sizeof(a));a.index=idx;
            a.is_closed=!!(state&1);a.markup_stream=!!(state&2);
            a.prefixed_by_markup=!!(state&4);a.unsigned_num=false;
            if(state&8)a.buffer[idx]=0;
            memcpy(&b,&a,sizeof(b));calls=hash=0;
            write_token(&a,test,false);
            unsigned nc=calls,signature=hash;callbacks+=calls;calls=hash=0;
            write_token(&b,test,true);
            if(memcmp(&a,&b,sizeof(a))||nc!=calls||signature!=hash) {
                fprintf(stderr,"token=%u index=%zu state=%u formatter=%u\n",test,idx,state,behavior);return 2;
            }
            ++count;
         }
    }
    cs_vsnprintf=standard;
    printf("%u %u\n",count,callbacks);
}
