#include "cs_priv.h"
#include "arch/X86/X86DisassemblerTranslator.h"
#include "paths.inc"
#include "descriptors.inc"
#include <stdio.h>

static int verify(unsigned opcode, const struct InstructionSpecifier *spec,
                  unsigned seed, bool emit, bool missing)
{
    InternalInstruction raw[2];
    MCInst mc[2];
    const uint8_t bytes[16] = {0};
    memset(raw, 0, sizeof(raw));
    memset(mc, 0, sizeof(mc));
    memset(mc[0].Operands, 0x37 + seed, sizeof(mc[0].Operands));
    memset(mc[1].Operands, 0x37 + seed, sizeof(mc[1].Operands));
    bool failed[2];
    for (unsigned k = 0; k < 2; ++k) {
        InternalInstruction *i = &raw[k];
        i->code = bytes;
        i->codeSize = sizeof(bytes);
        i->mode = (DisassemblerMode)(seed % 3);
        i->addressSize = 2u << (seed % 3);
        i->operandSize = 1u << (seed % 4);
        i->registerSize = i->operandSize;
        i->immediateSize = i->operandSize;
        i->displacementSize = i->addressSize;
        i->immSize = i->immediateSize;
        i->reg = MODRM_REG_RAX;
        i->opcodeRegister = MODRM_REG_CL;
        i->vvvv = MODRM_REG_XMM2;
        i->writemask = (Reg)(seed % 10);
        i->eaBase = (EABase[]){EA_BASE_NONE, EA_BASE_sib64, EA_BASE_BX_SI, EA_BASE_RAX, EA_REG_RAX, EA_REG_XMM2}[seed % 6];
        i->eaRegBase = EA_REG_RAX;
        i->sibBase = (seed & 1) ? SIB_BASE_RAX : SIB_BASE_NONE;
        i->sibIndex = (seed & 1) ? SIB_INDEX_XMM2 : SIB_INDEX_NONE;
        i->sibScale = 1u << (seed % 4);
        i->segmentOverride = (SegmentOverride)(seed % SEG_OVERRIDE_max);
        i->immediates[0] = UINT64_C(0x807fff80) + seed;
        i->immediates[1] = UINT64_C(0xffffffffff8000ff) - seed;
        i->modRM = i->orgModRM = (seed % 3 ? 0xc0 : 0x05) | (seed & 7);
        i->rex2Prefix = (uint8_t)(seed * 27);
        i->hasRex2 = seed & 1;
        i->apxEvexB4 = seed & 2;
        i->apxEvexX4 = seed & 4;
        i->apxEvexGprIndex = seed & 8;
        i->hasAdSize = seed & 4;
        i->xAcquireRelease = seed & 1;
        i->numImmediatesTranslated = 1;
        i->instructionID = opcode;
        i->spec = missing ? NULL : spec;
        i->operands = x86OperandSets[spec->operands];
        failed[k] = k ? descriptorLoop(&mc[k], i, emit) : generatedSwitch(&mc[k], i, emit);
    }
    if (failed[0] != failed[1] || memcmp(raw,raw+1,sizeof(*raw)) ||
        memcmp(mc,mc+1,sizeof(*mc))) {
        fprintf(stderr,"translator mismatch opcode %u operand set %u seed %u emit %u missing %u\n",
                opcode,spec->operands,seed,(unsigned)emit,(unsigned)missing);
        return 1;
    }
    return 0;
}
int main(void)
{
    unsigned states = 0, rows = 0;
    for (unsigned id = 0; id < sizeof(x86DisassemblerInstrSpecifiers)/sizeof(*x86DisassemblerInstrSpecifiers); ++id) {
        const struct InstructionSpecifier *spec = x86DisassemblerInstrSpecifiers + id;
        if (!affected[spec->operands] && id != X86_UD1) continue;
        ++rows;
        for (unsigned s = 0; s < 20; ++s)
            for (unsigned emit = 0; emit < 2; ++emit) {
                if (verify(id,spec,s,emit,false)) return 1;
                ++states;
            }
    }
    for (unsigned k = 0; k < 2; ++k) {
        if (verify(0,x86DisassemblerInstrSpecifiers,0,k,true)) return 1;
        ++states;
    }
    printf("Verified %u complete translator states across %u opcode rows\n",states,rows);
    return 0;
}
