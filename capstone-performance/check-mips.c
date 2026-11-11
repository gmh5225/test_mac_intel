#include "Mapping.h"
#include "arch/Mips/MipsMapping.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

#define GET_INSTRINFO_ENUM
#include "arch/Mips/MipsGenInstrInfo.inc"

extern void Mips_set_instr_map_data(MCInst *);
typedef void (*map_fn)(MCInst *);

static int compare(cs_struct *handle, map_fn baseline, unsigned op,
                   unsigned seed, unsigned variant, unsigned occupied)
{
    cs_insn insns[2];
    cs_detail details[2];
    memset(insns, (unsigned char)(0xa5 - seed), sizeof(insns));
    memset(details, (unsigned char)(0x51 + seed), sizeof(details));
    handle->detail_opt = (variant & 1) ? CS_OPT_ON : CS_OPT_OFF;
    handle->mode = (variant & 2) ? CS_MODE_MIPS16 : CS_MODE_MIPS64;
    for (unsigned k = 0; k < 2; ++k) {
        MCInst mi = { 0 };
        mi.csh = handle;
        mi.Opcode = op;
        mi.flat_insn = &insns[k];
        MCOperand_CreateReg0(&mi, seed % 3 == 0 ? MIPS_REG_RA :
                                  seed % 3 == 1 ? MIPS_REG_RA_64 : MIPS_REG_ZERO);
        MCOperand_CreateImm0(&mi, -(int64_t)seed);
        details[k].regs_read_count = seed % 9;
        details[k].regs_write_count = seed % 11;
        details[k].groups_count = occupied;
        if (occupied) details[k].groups[0] = MIPS_FEATURE_HASSTDENC;
        insns[k].detail = (variant & 4) ? &details[k] : NULL;
        (k ? Mips_set_instr_map_data : baseline)(&mi);
        insns[k].detail = NULL;
    }
    if (memcmp(insns, insns + 1, sizeof(*insns)) ||
        memcmp(details, details + 1, sizeof(*details))) {
        fprintf(stderr, "MIPS mismatch opcode %u seed %u variant %u occupied %u\n",
                op, seed, variant, occupied);
        return 1;
    }
    return 0;
}
int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    map_fn baseline = module ? (map_fn)dlsym(module, "Mips_set_instr_map_data") : NULL;
    if (!baseline) return 2;
    cs_struct handle = {0};
    handle.arch = CS_ARCH_MIPS;
    unsigned matched = 0;
    for (unsigned op = 0; op < INSTRUCTION_LIST_END; ++op)
        for (unsigned seed = 0; seed < 12; ++seed)
            for (unsigned variant = 0; variant < 8; ++variant) {
                if (compare(&handle, baseline, op, seed, variant, seed % 6)) return 1;
                ++matched;
            }
    unsigned codes[] = {Mips_ADDu, Mips_LW, Mips_JR, Mips_Save16};
    for (unsigned i = 0; i < sizeof(codes) / sizeof(*codes); ++i)
        for (unsigned n = MAX_NUM_GROUPS - 3; n <= MAX_NUM_GROUPS; ++n) {
            if (compare(&handle, baseline, codes[i], 5, 7, n)) return 1;
            ++matched;
        }
    printf("Verified %u complete MIPS mapper states\n", matched);
    dlclose(module);
    return 0;
}
