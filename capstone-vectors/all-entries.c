#include <capstone/capstone.h>

typedef bool (*Iterator)(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *);
extern bool X86_disasmIter(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *);
extern bool X86_disasmIter32(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *);
extern bool X86_disasmIterText(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *);
static Iterator entry;

void choose_entry(const char *label, unsigned bits)
{
    switch (label[0]) {
    case 'w': entry = X86_disasmIterText; break;
    case 'n': entry = bits == 32 ? X86_disasmIter32 : X86_disasmIter; break;
    default: entry = X86_disasmIter; break;
    }
}

bool selected(csh h, const uint8_t **c, size_t *n, uint64_t *ip, cs_insn *i)
{
    return entry(h, c, n, ip, i);
}
