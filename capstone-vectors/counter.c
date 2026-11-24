#include <inttypes.h>
#include <stdio.h>
#include <capstone/capstone.h>
typedef struct X86ScanResult X86ScanResult;
bool __real_X86_getInstructionScanResult(csh handle, const uint8_t *code,
    size_t size, cs_insn *insn, X86ScanResult *result);
static uint64_t total, map[256];
bool __wrap_X86_getInstructionScanResult(csh handle, const uint8_t *code,
    size_t size, cs_insn *insn, X86ScanResult *result)
{
    ++total;
    if (size >= 5 && code[0] == 0x66) {
        size_t i=1 + ((code[1]&0xf0)==0x40);
        if (size>=i+4 && code[i]==0x0f && code[i+1]==0x38 && code[i+3]>=0xc0)
            ++map[code[i+2]];
    }
    return __real_X86_getInstructionScanResult(handle,code,size,insn,result);
}
__attribute__((destructor)) static void report(void)
{
    fprintf(stderr,"%" PRIu64, total);
    for (unsigned i=0; i<256; ++i) fprintf(stderr," %" PRIu64,map[i]);
    fputc('\n',stderr);
}
