#include "arch/RISCV/RISCVMapping.h"
#include <stdio.h>
#include <string.h>

int main(void)
{
    cs_struct handle = { 0 };
    cs_insn insn = { 0 };
    MCInst mi = { 0 };
    cs_detail detail = { 0 };
    insn.detail = &detail;
    handle.detail_opt = CS_OPT_ON;
    mi.csh = &handle;
    mi.flat_insn = &insn;
    unsigned cases = 0;
    for (unsigned mask = 0; mask < (1u << NUM_RISCV_OPS); ++mask)
        for (unsigned count = 0; count <= NUM_RISCV_OPS + 2; ++count)
            for (unsigned dirt = 0; dirt < 3; ++dirt) {
                cs_riscv_op expected[NUM_RISCV_OPS] = { 0 };
                unsigned out = 0;
                for (unsigned i = 0; i < NUM_RISCV_OPS; ++i) {
                    cs_riscv_op *op = &detail.riscv.operands[i];
                    memset(op, dirt == 2 || (dirt == 1 && (i & 1)) ? 0xaa : 0,
                           sizeof(*op));
                    op->type = mask & (1u << i) ? RISCV_OP_IMM : RISCV_OP_INVALID;
                    if (op->type != RISCV_OP_INVALID) {
                        op->imm = (int64_t)(i + mask * 8);
                        memcpy(expected + out++, op, sizeof(*op));
                    }
                }
                detail.riscv.op_count = count;
                RISCV_compact_operands(&mi);
                if (detail.riscv.op_count != count ||
                    memcmp(detail.riscv.operands, expected, sizeof(expected)))
                    return 1;
                ++cases;
            }
    printf("%u\n", cases);
    return 0;
}
