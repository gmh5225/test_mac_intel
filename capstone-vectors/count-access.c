#include "arch/X86/X86Mapping.h"
#include <inttypes.h>
#include <stdio.h>

static uint64_t calls;

const uint8_t *__real_X86_get_op_access(cs_struct *handle, unsigned opcode,
					uint64_t *flags);

const uint8_t *__wrap_X86_get_op_access(cs_struct *handle, unsigned opcode,
					uint64_t *flags)
{
	++calls;
	return __real_X86_get_op_access(handle, opcode, flags);
}

__attribute__((destructor)) static void report_calls(void)
{
	fprintf(stderr, "access_lookup_calls=%" PRIu64 "\n", calls);
}
