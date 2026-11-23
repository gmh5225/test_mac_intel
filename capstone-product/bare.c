#include "arch/X86/X86SimpleOutput.h"
#include "arch/X86/X86ScanAdapter.h"
bool observed_bare(const uint8_t *bytes, size_t length, bool wide)
{
    if (!length || (bytes[0] != 0xc4 && bytes[0] != 0xc5)) return false;
    const unsigned prefix = bytes[0] == 0xc5 ? 2 : 3;
    if (length < prefix + 2 || (bytes[prefix - 1] & 3) ||
        bytes[prefix + 1] < 0xc0 || (prefix == 3 && (bytes[1] & 31) != 1)) return false;
    if (!wide && (prefix == 2 ? (bytes[1] & 0xc0) != 0xc0 :
        (bytes[1] & 0xe0) != 0xe0 || (bytes[2] & 0xc0) != 0x40)) return false;
    cs_insn out = { 0 };
    uint16_t size;
    return X86_writeVectorOutput(bytes, length, &out, &size, NULL, true);
}
