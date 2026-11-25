#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static unsigned checks;
static int verify(csh handle, cs_mode mode, int override)
{
    unsigned bits = (mode & CS_MODE_16) ? 16 : (mode & CS_MODE_32) ? 32 : 64;
    unsigned width = override ? (bits == 32 ? 16 : 32) : bits;
    uint8_t bytes[9];
    unsigned size = 0;
    if (override) bytes[size++] = 0x67;
    bytes[size++] = 0x8b;
    if (bits == 64) {
        bytes[size++] = 0x04;
        bytes[size++] = 0x25;
    } else {
        bytes[size++] = width == 16 ? 0x06 : 0x05;
    }
    int64_t raw;
    if (width == 16) {
        bytes[size++] = 0x34; bytes[size++] = 0x82;
        raw = -((int64_t)0x7dcc);
    } else {
        bytes[size++] = 0x34; bytes[size++] = 0x12;
        bytes[size++] = 0x00; bytes[size++] = 0x80;
        raw = INT64_C(0x80001234) - INT64_C(0x100000000);
    }
    uint64_t absolute = (uint64_t)raw;
    if (width == 16) absolute &= UINT16_MAX;
    else if (width == 32) absolute &= UINT32_MAX;
    char number[32];
    snprintf(number, sizeof(number), "0x%" PRIx64, absolute);
    for (int att = 0; att < 2; ++att) {
        int syntax = att ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL;
        if (cs_option(handle, CS_OPT_SYNTAX, syntax) != CS_ERR_OK) return 2;
        for (int details = 0; details < 2; ++details) {
            if (cs_option(handle, CS_OPT_DETAIL, details ? CS_OPT_ON : CS_OPT_OFF)) return 3;
            cs_insn *insn = NULL;
            size_t count = cs_disasm(handle, bytes, size, 0x1000, 1, &insn);
            if (!count || insn->size != size || !strstr(insn->op_str, number)) {
                fprintf(stderr, "mode %u bits %u width %u expected %s got %s\n",
                        (unsigned)mode,bits,width,number,count ? insn->op_str : "invalid");
                return 4;
            }
            if (details) {
                cs_x86 *x = &insn->detail->x86;
                if (x->addr_size != width/8 || x->disp != raw || x->op_count != 2) return 5;
                cs_x86_op *mem = &x->operands[att ? 0 : 1];
                if (mem->type != X86_OP_MEM || mem->mem.disp != raw) return 6;
            }
            ++checks;
            cs_free(insn,count);
        }
    }
    return 0;
}
int main(void)
{
    const unsigned modes[] = {CS_MODE_16,CS_MODE_32,CS_MODE_64,0,
                              CS_MODE_16|CS_MODE_32, CS_MODE_16|CS_MODE_64,
                              CS_MODE_32|CS_MODE_64,CS_MODE_16|CS_MODE_32|CS_MODE_64};
    const unsigned vendors[] = {0,CS_MODE_X86_INTEL,CS_MODE_X86_AMD};
    for (unsigned start=0;start<8;++start) {
        csh h;
        if (cs_open(CS_ARCH_X86,modes[start],&h)) return 7;
        int value;
        for (int prefix=0;prefix<2;++prefix)
            if ((value=verify(h,modes[start],prefix))) return value;
        for (unsigned n=0;n<8;++n) for (unsigned v=0;v<3;++v) {
            cs_mode mode = (cs_mode)(modes[(n+start)%8]|vendors[v]);
            if (cs_option(h,CS_OPT_MODE,mode)) return 8;
            if (cs_option(h,CS_OPT_MODE, mode|CS_MODE_X86_INTEL|CS_MODE_X86_AMD)==CS_ERR_OK) return 9;
            for (int prefix=0;prefix<2;++prefix)
                if ((value=verify(h,mode,prefix))) return value;
        }
        cs_close(&h);
    }
    printf("%u\n",checks);
    return checks != 1600;
}
