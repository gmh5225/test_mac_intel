#include <stdio.h>
#include "MCInst.h"
int main(void) {
    printf("{\"size\":%zu,\"ac_idx\":%zu,\"assembly\":%zu,\"evm_data\":%zu,\"wasm_data\":%zu,\"MRI\":%zu,\"xAcquireRelease\":%zu,\"x86Lock\":%zu,\"isAliasInstr\":%zu,\"fillDetailOps\":%zu,\"hppa_ext\":%zu,\"MAI\":%zu}\n",
        sizeof(MCInst),
        offsetof(MCInst, ac_idx),
        offsetof(MCInst, assembly),
        offsetof(MCInst, evm_data),
        offsetof(MCInst, wasm_data),
        offsetof(MCInst, MRI),
        offsetof(MCInst, xAcquireRelease),
        offsetof(MCInst, x86Lock),
        offsetof(MCInst, isAliasInstr),
        offsetof(MCInst, fillDetailOps),
        offsetof(MCInst, hppa_ext),
        offsetof(MCInst, MAI));
    return 0;
}
