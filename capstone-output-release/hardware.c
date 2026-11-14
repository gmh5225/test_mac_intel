#include <stdint.h>
#include <stdio.h>

int main(void)
{
	uint64_t seed = UINT64_C(0xf1357aea2e62a9c5);
	for (unsigned i = 0; i < 4096; ++i) {
		seed ^= seed << 13;
		seed ^= seed >> 7;
		seed ^= seed << 17;
		uint64_t value = seed;
		__asm__ volatile(".byte 0xa8, 0x81" : "+a"(value) : : "cc");
		if (value != seed)
			return 1;
		__asm__ volatile(".byte 0x66, 0xa9\n\t.short 0x8001"
				 : "+a"(value) : : "cc");
		if (value != seed)
			return 2;
		__asm__ volatile(".byte 0xa9\n\t.long 0x80000001"
				 : "+a"(value) : : "cc");
		if (value != seed)
			return 3;
		__asm__ volatile(".byte 0x48, 0xa9\n\t.long 0x80000001"
				 : "+a"(value) : : "cc");
		if (value != seed)
			return 4;
	}
	puts("16384 native TEST accumulator executions preserved RAX");
	return 0;
}
