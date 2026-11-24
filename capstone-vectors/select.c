#include <stdlib.h>
#include "cs_priv.h"
typedef void Printer(MCInst *, SStream *);
extern Printer __real_X86_Intel_printInstructionPrechecked, measure_address, measure_regprefix;
static Printer *selected;
static void detected(MCInst *mi, SStream *ss) { _Exit(73); }
void measure_select_printer(int i) {
    Printer *const functions[]={__real_X86_Intel_printInstructionPrechecked,measure_address,measure_regprefix,detected};
    if ((unsigned)i>=4) abort();
    selected=functions[i];
}
void __wrap_X86_Intel_printInstructionPrechecked(MCInst *mi,SStream *ss) { selected(mi,ss); }
