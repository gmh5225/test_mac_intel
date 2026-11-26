#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include "arch/X86/X86Mapping.h"
#include "arch/X86/X86FeatureExtension.h"
#define GET_REGINFO_ENUM
#include "arch/X86/X86GenRegisterInfo.inc"

static const struct { unsigned internal, external; } rows[] = {
    {0, 0},
#include "arch/X86/X86MappingReg.inc"
};
int main(void)
{
    const unsigned count = sizeof(rows) / sizeof(rows[0]);
    if (count > X86_FEATURE_MC_GPR_BASE) return 1;
    const unsigned first[] = {X86_REG_R16B, X86_REG_R16W, X86_REG_R16D, X86_REG_R16};
    uint64_t digest = UINT64_C(14695981039346656037);
    unsigned legacy=0, extended=0, unmapped=0;
    for (unsigned id=0; id<=UINT16_MAX; ++id) {
        unsigned expected=X86_REG_INVALID;
        if (id<count) {
            if (rows[id].internal != id) return 2;
            expected=rows[id].external;
        } else if (id>=X86_FEATURE_MC_GPR_BASE && id<X86_FEATURE_MC_GPR_BASE+64) {
            unsigned offset=id-X86_FEATURE_MC_GPR_BASE;
            expected=first[offset/16]+offset%16;
        }
        const unsigned got=X86_register_map((unsigned short)id);
        if (expected!=got) { fprintf(stderr, "%u %u %u\n",id,expected,got); return 3; }
        if (!got) ++unmapped;
        else if (id<count) ++legacy;
        else ++extended;
        digest=(digest^got)*UINT64_C(1099511628211);
    }
    if (!legacy || extended!=64 || unmapped+extended+legacy!=65536) return 4;
    printf("%u %u %u %llu\n",legacy,extended,unmapped,(unsigned long long)digest);
    return 0;
}
