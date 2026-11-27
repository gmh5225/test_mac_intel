#include "raw.h"
void measure_raw_operands(const uint8_t *code, size_t length, cs_mode mode, ReaderState *out)
{
    memset(out, 0, sizeof(*out));
    InternalInstruction *i = &out->instruction;
    out->status = decodeInstruction(i, code, length, mode);
    out->set = i->spec ? i->spec->operands : -1;
    out->has_operands = i->operands != NULL;
    if (i->operands)
        memcpy(out->operands, i->operands, sizeof(out->operands));
    /* Static pointers belong to different libraries. Compare their contents. */
    i->spec = NULL;
    i->operands = NULL;
}
