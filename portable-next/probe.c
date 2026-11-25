#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static uint64_t digest = UINT64_C(14695981039346656037);
static void mix(const void *data, size_t size)
{
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < size; ++i)
        digest = (digest ^ p[i]) * UINT64_C(1099511628211);
}

int main(void)
{
    unsigned accepted = 0, rejected = 0;
    for (unsigned wide = 0; wide != 2; ++wide) {
        for (unsigned big = 0; big != 2; ++big) {
            const cs_mode mode = (cs_mode)((wide ? CS_MODE_MIPS64R2 : CS_MODE_MIPS32R2)
                                | (big ? CS_MODE_BIG_ENDIAN : 0));
            for (unsigned dialect = 0; dialect != 4; ++dialect) {
                csh h = 0;
                if (cs_open(CS_ARCH_MIPS, mode, &h)) return 1;
                if (cs_option(h, CS_OPT_SYNTAX, ((dialect & 1) ? CS_OPT_SYNTAX_NOREGNAME : 0)
                                                | ((dialect & 2) ? CS_OPT_SYNTAX_NO_DOLLAR : 0))) return 2;
                if (cs_option(h, CS_OPT_DETAIL, CS_OPT_ON)) return 3;
                cs_insn *insn = cs_malloc(h);
                if (!insn) return 4;
                for (unsigned major = 0; major < 64; ++major) {
                    for (unsigned reg = 0; reg < 32; ++reg) {
                        uint32_t word = major << 26 | reg << 21 | ((reg + 7) & 31) << 16
                                        | reg << 11 | (reg & 1 ? 0x21 : 0x2d);
                        uint8_t bytes[4];
                        for (unsigned i = 0; i < 4; ++i) bytes[big ? 3-i : i] = (uint8_t)(word >> (8 * i));
                        const uint8_t *p = bytes; size_t left = 4; uint64_t addr = 0x1000;
                        if (cs_disasm_iter(h, &p, &left, &addr, insn)) {
                            if (p != bytes + 4 || left || addr != 0x1004) return 5;
                            mix(&insn->id, sizeof insn->id);
                            mix(insn->bytes, insn->size);
                            mix(insn->mnemonic, strlen(insn->mnemonic) + 1);
                            mix(insn->op_str, strlen(insn->op_str) + 1);
                            if (insn->detail) {
                                mix(&insn->detail->mips.op_count, 1);
                                for (unsigned i = 0; i < insn->detail->mips.op_count; ++i) {
                                    const cs_mips_op *op = &insn->detail->mips.operands[i];
                                    mix(&op->type, sizeof op->type);
                                    if (op->type == MIPS_OP_REG) mix(&op->reg, sizeof op->reg);
                                    else if (op->type == MIPS_OP_IMM) mix(&op->imm, sizeof op->imm);
                                    else if (op->type == MIPS_OP_MEM) {
                                        mix(&op->mem.base, sizeof op->mem.base);
                                        mix(&op->mem.disp, sizeof op->mem.disp);
                                    }
                                }
                            }
                            ++accepted;
                        } else {
                            if (p != bytes || left != 4 || addr != 0x1000) return 6;
                            ++rejected;
                        }
                    }
                }
                cs_free(insn, 1); cs_close(&h);
            }
        }
    }
    if (!accepted || !rejected || accepted + rejected != 32768) return 7;
    printf("%u %u %" PRIu64 "\n", accepted, rejected, digest);
    return 0;
}
