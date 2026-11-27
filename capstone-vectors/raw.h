#include "arch/X86/X86DisassemblerDecoder.h"
#include <string.h>
typedef struct ReaderState {
    InternalInstruction instruction;
    int status;
    int set;
    int has_operands;
    OperandSpecifier operands[X86_MAX_OPERANDS];
} ReaderState;
