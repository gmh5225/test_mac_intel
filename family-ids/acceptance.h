#include <cstdlib>
#include <cstdio>
#include <cstring>
// Apply the specified correction to the previous public record after validating
// every affected register on both sides. The surrounding byte comparison still
// includes every other detail field, all text, unused bytes and cursor state.
static bool expect_vector_writes(unsigned bits, unsigned id, cs_detail &old, const cs_detail &now)
{
    if (bits==64 || (id!=X86_INS_VZEROALL && id!=X86_INS_VZEROUPPER))
        return false;
    if (old.regs_write_count!=16 || now.regs_write_count!=8)
        std::abort();
    for (unsigned i=0; i<16; ++i) {
        if (old.regs_write[i]!=X86_REG_YMM0+i ||
            now.regs_write[i]!=(i<8 ? X86_REG_YMM0+i : 0)) {
            std::fprintf(stderr,"unexpected register %u in vector-clear record\n",i);
            std::abort();
        }
    }
    old.regs_write_count=8;
    std::memset(old.regs_write+8,0,8*sizeof(old.regs_write[0]));
    return true;
}
static unsigned vector_write_score_delta()
{
    unsigned delta=8;
    for (unsigned i=8; i<16; ++i)
        delta+=X86_REG_YMM0+i;
    return delta;
}
