#include <capstone/capstone.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "arch/X86/X86ScanAdapter.h"

static bool check(csh handles[2], const uint8_t *bytes, size_t length,
                  unsigned flags, unsigned seed)
{
    cs_insn insn[2];
    cs_detail detail[2];
    const uint8_t *next[2] = {bytes, bytes};
    size_t left[2] = {length, length};
    uint64_t ip[2] = {0x7ffffff0, 0x7ffffff0};
    bool ok[2];
    for (unsigned i = 0; i < 2; ++i) {
        memset(&insn[i], seed, sizeof(insn[i]));
        memset(&detail[i], seed, sizeof(detail[i]));
        insn[i].usesAliasDetails = insn[i].is_alias = insn[i].illegal = false;
        cs_detail *storage = (flags & 1) ? &detail[i] : NULL;
        insn[i].detail = storage;
        ok[i] = (i ? cs_disasm_iter : X86_disasmIterText)(
            handles[i], &next[i], &left[i], &ip[i], &insn[i]);
        if (insn[i].detail != storage)
            return false;
        insn[i].detail = NULL;
    }
    return ok[0] == ok[1] && left[0] == left[1] && next[0] == next[1] &&
           ip[0] == ip[1] && cs_errno(handles[0]) == cs_errno(handles[1]) &&
           memcmp(&insn[0], &insn[1], sizeof(cs_insn)) == 0 &&
           memcmp(&detail[0], &detail[1], sizeof(cs_detail)) == 0;
}
int main(void)
{
    const cs_mode modes[] = {CS_MODE_16, CS_MODE_32, CS_MODE_64};
    const uint8_t cases[][15] = {
        {0x90}, {0x31,0xc0}, {0x48,0x89,0xd8}, {0x0f,0x0b},
        {0xc5,0xaa,0xc2,0x30,0x02,0xa0}, {0xc5,0xf8,0xc2,0xc1,6},
        {0xc5,0xfd,0x6f,0x40,0x7f}, {0xc5,0xed,0xef,0xc1},
        {0xc4,0xe2,0x6d,0x00,0xc1}, {0x62,0xf1,0x7e,0x48,0x6f,0x08},
        {0xc7,0x44,0x24,0x04,0x30,0x11,0x40,0}, {0xc6,0x40,0x7f,0xff},
        {0x48,0xc7,0x44,0x24,0x08,0xff,0xff,0xff,0xff},
        {0x49,0xc7,0x04,0x24,0,0,0,0x80},
        {0x44,0x0f,0x58,0x3d,0x01,0,0,0},
        {0x48,0xc7,0x05,0xef,0xff,0xff,0xff,10,0,0,0}
    };
    unsigned n=0;
    for (unsigned m=0; m<3; ++m) for (unsigned f=0; f<16; ++f) {
        csh h[2] = {0};
        cs_err options[2][4];
        for (unsigned k=0; k<2; ++k) {
            if (cs_open(CS_ARCH_X86,modes[m],&h[k]) != CS_ERR_OK) return 1;
            options[k][0]=cs_option(h[k],CS_OPT_DETAIL,(f&1)?CS_OPT_ON:CS_OPT_OFF);
            options[k][1]=cs_option(h[k],CS_OPT_TEXT,(f&2)?CS_OPT_OFF:CS_OPT_ON);
            options[k][2]=cs_option(h[k],CS_OPT_SYNTAX,(f&4)?CS_OPT_SYNTAX_ATT:CS_OPT_SYNTAX_INTEL);
            options[k][3]=cs_option(h[k],CS_OPT_UNSIGNED,(f&8)?CS_OPT_ON:CS_OPT_OFF);
        }
        if (memcmp(options[0],options[1],sizeof(options[0]))) return 2;
        for (unsigned v=0; v<sizeof(cases)/sizeof(cases[0]); ++v) {
            for(unsigned k=0;k<=sizeof(cases[0]);++k) {
                if (!check(h,cases[v],k,f,(v+n)%255)) {
                    fprintf(stderr,"m=%u flags=%u case=%u size=%u\n",m,f,v,k);
                    return 3;
                }
                ++n;
            }
        }
        cs_close(&h[0]);cs_close(&h[1]);
    }
    printf("%u raw iterator comparisons\n",n);
    return 0;
}
