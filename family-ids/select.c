#include "cs_priv.h"
#include "arch/RISCV/RISCVLinkage.h"
#include <stdlib.h>

extern cs_err __real_cs_open(cs_arch, cs_mode, csh *);
extern void copy_RISCV_LLVM_printInstruction(MCInst *, SStream *, void *);
extern void lazy_RISCV_LLVM_printInstruction(MCInst *, SStream *, void *);
extern void width_RISCV_LLVM_printInstruction(MCInst *, SStream *, void *);

cs_err __wrap_cs_open(cs_arch arch, cs_mode mode, csh *handle)
{
	cs_err error = __real_cs_open(arch, mode, handle);
	if (error == CS_ERR_OK && arch == CS_ARCH_RISCV) {
		static const Printer_t printers[] = {
			RISCV_LLVM_printInstruction,
			copy_RISCV_LLVM_printInstruction,
			lazy_RISCV_LLVM_printInstruction,
			width_RISCV_LLVM_printInstruction,
		};
		const char *variant = getenv("RV_PRINTER");
		if (!variant || variant[0] < '0' || variant[0] > '3' || variant[1])
			abort();
		cs_struct *h = (cs_struct *)(uintptr_t)*handle;
		if (h->printer != printers[0])
			abort();
		h->printer = printers[variant[0] - '0'];
	}
	return error;
}
