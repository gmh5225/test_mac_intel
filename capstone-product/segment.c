#define X86_decodeOutputMiss32 test_memory_miss
#define X86_decodeRegisterFallback32 test_register_miss
#include "arch/X86/X86MemoryFallback32.c"

CS_PRESERVE_MOST bool test_register_miss(cs_struct *handle, const uint8_t *code,
		size_t size, cs_insn *insn, uint16_t *length, bool batch)
{
	return false;
}

bool observed_plain(csh h, bool wide, const uint8_t *code, size_t size,
		    cs_insn *insn, uint16_t *length)
{
	return !wide && size && test_memory_miss((cs_struct *)(uintptr_t)h,
				code, size, insn, length, false);
}
