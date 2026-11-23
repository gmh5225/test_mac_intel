#include "arch/SystemZ/SystemZMapping.h"
#define GET_INSTRINFO_ENUM
#include "arch/SystemZ/SystemZGenInstrInfo.inc"
#include <stdio.h>
#include <string.h>

extern const insn_map systemz_insns[];
void SystemZ_set_instr_map_data(MCInst *, const uint8_t *, size_t);

int main(void)
{
    cs_struct handle = { 0 };
    handle.arch = CS_ARCH_SYSTEMZ;
    unsigned checks = 0;
    for (unsigned op = 0; op < INSTRUCTION_LIST_END; ++op) {
        for (unsigned state = 0; state < 4; ++state) {
            MCInst ref = { 0 }, got = { 0 };
            cs_detail a, b;
            cs_insn x, y;
            memset(&x, 0xa5, sizeof(x));
            memcpy(&y, &x, sizeof(y));
            memset(&a, 0x5a, sizeof(a));
            a.regs_read_count = a.regs_write_count = a.groups_count = state > 1 ? state - 1 : 0;
            memcpy(&b, &a, sizeof(a));
            x.detail = state ? &a : NULL;
            y.detail = state ? &b : NULL;
            handle.detail_opt = state ? CS_OPT_ON : CS_OPT_OFF;
            got.csh = ref.csh = &handle;
            ref.flat_insn = &x;
            got.flat_insn = &y;
            MCInst_setOpcode(&ref, op);
            MCInst_setOpcode(&got, op);
            map_cs_id(&ref, systemz_insns, INSTRUCTION_LIST_END);
            map_implicit_reads(&ref, systemz_insns);
            map_implicit_writes(&ref, systemz_insns);
            map_groups(&ref, systemz_insns);
            const systemz_suppl_info *suppl = map_get_suppl_info(&ref, systemz_insns);
            if (suppl) a.systemz.format = suppl->form;
            SystemZ_set_instr_map_data(&got, NULL, 0);
            if (x.detail != (state ? &a : NULL) || y.detail != (state ? &b : NULL))
                return 1;
            x.detail = y.detail = NULL;
            if (memcmp(&x, &y, sizeof(x)) || memcmp(&a, &b, sizeof(a))) {
                fprintf(stderr, "opcode %u state %u\n", op, state);
                return 1;
            }
            ++checks;
        }
    }
    printf("%u\n",checks);
    return 0;
}
