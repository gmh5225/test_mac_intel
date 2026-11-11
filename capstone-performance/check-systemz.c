#include "arch/SystemZ/SystemZMapping.h"
#include "Mapping.h"
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
extern void SystemZ_set_instr_map_data(MCInst *, const uint8_t *, size_t);
typedef void (*map_fn)(MCInst *, const uint8_t *, size_t);
int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    void *module = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    map_fn original = module ? (map_fn)dlsym(module, "SystemZ_set_instr_map_data") : NULL;
    if (!original) return 2;
    unsigned matched = 0;
    cs_struct handle = { 0 };
    handle.arch = CS_ARCH_SYSTEMZ;
    for (unsigned opcode = 0; opcode < 3105; ++opcode) {
        for (unsigned seed = 0; seed < 12; ++seed) {
            for (unsigned mode = 0; mode < 4; ++mode) {
                cs_insn insns[2];
                cs_detail detail[2];
                memset(insns, 0xa5 - seed, sizeof(insns));
                memset(detail, 0x51 + seed, sizeof(detail));
                handle.detail_opt = (mode & 1) ? CS_OPT_ON : CS_OPT_OFF;
                for (unsigned k = 0; k < 2; ++k) {
                    MCInst mi = { 0 };
                    mi.csh = &handle;
                    mi.Opcode = opcode;
                    mi.flat_insn = &insns[k];
                    detail[k].regs_read_count = seed % 9;
                    detail[k].regs_write_count = seed % 11;
                    detail[k].groups_count = seed % 6;
                    insns[k].detail = mode & 2 ? &detail[k] : NULL;
                    (k ? SystemZ_set_instr_map_data : original)(&mi, NULL, 0);
                    insns[k].detail = NULL;
                }
                if (memcmp(insns, insns + 1, sizeof(*insns)) ||
                    memcmp(detail, detail + 1, sizeof(*detail))) {
                    fprintf(stderr,"SystemZ mismatch at %u seed %u mode %u\n",opcode,seed,mode);
                    return 1;
                }
                ++matched;
            }
        }
    }
    printf("Verified %u complete SystemZ states against the published mapper\n", matched);
    return 0;
}
