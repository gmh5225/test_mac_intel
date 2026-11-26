#include "cs_priv.h"
#include "MathExtras.h"
#include "SStream.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"
#include "MCInst.h"
#include "arch/X86/X86InstPrinterCommon.h"
#include "reference.c"
#include "immediate3458.c"
#include "immediate3459.c"

struct trace {
	char fmt[40];
	uint64_t arg;
	size_t capacity;
	unsigned calls;
};
static struct trace seen;
static unsigned policy;
static unsigned cases;

static int hooked(char *dst, size_t cap, const char *fmt, va_list args)
{
	va_list copy;
	va_copy(copy, args);
	seen.arg = va_arg(copy, uint64_t);
	va_end(copy);
	snprintf(seen.fmt, sizeof(seen.fmt), "%s", fmt);
	seen.capacity = cap;
	++seen.calls;
	if (policy == 2)
		return -1;
	if (policy == 3)
		return snprintf(dst, cap, "<value>");
	return vsnprintf(dst, cap, fmt, args);
}


static const uint8_t sizes[] = {0,1,2,3,4,8,16,255};
static const unsigned syntax[] = {CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_MASM, CS_OPT_SYNTAX_DEFAULT, CS_OPT_SYNTAX_ATT};
static const unsigned positions[] = {0,7,491,492,493,509,510,511,512,513};
static MCInst mi;
static cs_struct handle;

static void test(uint64_t bits, unsigned shape)
{
    mi.csh = &handle;
    mi.op1_size = sizes[shape%8];
    handle.syntax = syntax[(shape/8)%4];
    bool positive = (shape/32)%2;
    unsigned flags = shape/64%8;
    policy = shape/512%4;
    unsigned pos = positions[shape/2048%10];
    SStream initial, ref, trial;
    memset(&initial, 0x5a, sizeof(initial));
    initial.index = pos;
    if (pos<sizeof(initial.buffer)) initial.buffer[pos] = '\0';
    initial.is_closed = !!(flags&1); initial.markup_stream = !!(flags&2);
    initial.prefixed_by_markup = !!(flags&4); initial.unsigned_num = !!(bits&1);
    cs_vsnprintf = policy ? hooked : cs_default_vsnprintf;
    memcpy(&ref,&initial,sizeof(ref));memset(&seen,0,sizeof(seen));
    originalImmediate(&mi,&ref,(int64_t)bits,positive);struct trace expected=seen;
    for(unsigned variant=0;variant<2;++variant) {
        memcpy(&trial,&initial,sizeof(trial));memset(&seen,0,sizeof(seen));
        if(variant) immediate3459(&mi,&trial,(int64_t)bits,positive);
        else immediate3458(&mi,&trial,(int64_t)bits,positive);
        if(memcmp(&ref,&trial,sizeof(ref))||memcmp(&seen,&expected,sizeof(seen))) {
            fprintf(stderr,"variant %u value %"PRIx64" width %u syntax %d positive %d shape %u\n",variant,bits,mi.op1_size,handle.syntax,positive,shape);
            abort();
        }
        ++cases;
    }
}

int main(void) {
    const uint64_t values[] = {0,1,9,10,15,16,255,256,INT64_MAX,UINT64_C(1)<<63,UINT64_MAX,UINT64_MAX-8,
        UINT64_MAX-9, UINT64_C(0xffffffff00000001),UINT64_C(0xffffffffffff0008),UINT64_C(0xabcdef0123456789)};
    for(unsigned shape=0;shape<20480;++shape)
        for(unsigned i=0;i<sizeof(values)/sizeof(*values);++i)test(values[i],shape);
    uint64_t bits=1;
    for(unsigned i=0;i<1000000;++i) {
        bits=bits*UINT64_C(6364136223846793005)+1;
        test(bits,i%20480);
    }
    cs_vsnprintf=cs_default_vsnprintf;printf("%u\n",cases);
    return 0;
}
