#include "MCInst.h"
#include "cs_priv.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*Map)(MCInst *);
typedef void (*MapBytes)(MCInst *, const uint8_t *, size_t);

static void invoke(void *symbol, int bytes, unsigned opcode, unsigned policy,
                   cs_arch arch, cs_insn *out, cs_detail *detail)
{
    cs_struct handle = {0};
    MCInst mi = {0};
    const uint8_t input[] = {0xff, 0x01, 0x80, 0x40, 0x07, 0x00, 0x80, 0x00};
    memset(out, 0xa5, sizeof(*out));
    memset(detail, 0xa5, sizeof(*detail));
    detail->regs_read_count = 0;
    detail->regs_write_count = 0;
    detail->groups_count = 0;
    out->detail = policy ? detail : NULL;
    handle.arch = arch;
    handle.mode = CS_MODE_BIG_ENDIAN;
    handle.detail_opt = policy >= 2 ? CS_OPT_ON : CS_OPT_OFF;
    mi.csh = &handle;
    mi.flat_insn = out;
    mi.Opcode = opcode;
    if (bytes)
        ((MapBytes)symbol)(&mi, input, sizeof(input));
    else
        ((Map)symbol)(&mi);
    out->detail = NULL;
}

int main(int argc, char **argv)
{
    if (argc != 7)
        return 2;
    void *base = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    void *candidate = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!base || !candidate) {
        fprintf(stderr, "%s\n", dlerror());
        return 3;
    }
    const char *names[] = {"PPC_set_instr_map_data", "ARC_set_instr_map_data",
                           "LoongArch_set_instr_map_data", "SystemZ_set_instr_map_data"};
    const cs_arch arches[] = {CS_ARCH_PPC, CS_ARCH_ARC, CS_ARCH_LOONGARCH, CS_ARCH_SYSTEMZ};
    unsigned long checks = 0;
    for (unsigned arch = 0; arch < 4; ++arch) {
        unsigned count = (unsigned)strtoul(argv[arch + 3], NULL, 10);
        void *a = dlsym(base, names[arch]);
        void *b = dlsym(candidate, names[arch]);
        if (!a || !b || !count) {
            fprintf(stderr, "missing mapping boundary: %s\n", names[arch]);
            return 4;
        }
        for (unsigned policy = 0; policy < 3; ++policy) {
            for (unsigned opcode = 0; opcode < count + (policy == 0 ? 2 : 0); ++opcode) {
                cs_insn x, y;
                cs_detail xd, yd;
                unsigned value = opcode == count + 1 ? ~0U : opcode;
                invoke(a, arch == 0 || arch == 3, value, policy, arches[arch], &x, &xd);
                invoke(b, arch == 0 || arch == 3, value, policy, arches[arch], &y, &yd);
                if (memcmp(&x, &y, sizeof(x)) || memcmp(&xd, &yd, sizeof(xd))) {
                    fprintf(stderr, "mapping mismatch: %s opcode=%u policy=%u\n",
                            names[arch], value, policy);
                    return 5;
                }
                ++checks;
            }
        }
    }
    printf("equal %lu mapping states: absent detail, present/option-off, present/option-on, and invalid IDs without detail\n", checks);
    dlclose(candidate);
    dlclose(base);
    return 0;
}
