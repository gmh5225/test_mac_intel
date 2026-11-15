#define CAPSTONE_HAS_X86
#define CAPSTONE_USE_SYS_DYN_MEM
#define NDEBUG
#include "arch/X86/X86ImmediateOutput.c"
#include <inttypes.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

static uint64_t checked;

static void check_number(uint64_t value)
{
	unsigned char actual[64], expected[64];
	const unsigned offset = 8 + (value & 15);
	memset(actual, 0xa5, sizeof(actual));
	memset(actual + offset, 0, 24);
	memcpy(expected, actual, sizeof(actual));
	const int length = value <= HEX_THRESHOLD ?
		snprintf((char *)expected + offset, 24, "%" PRIu64, value) :
		snprintf((char *)expected + offset, 24, "0x%" PRIx64, value);
	if (length <= 0 || length >= 24)
		_exit(10);
	writeUnsignedImmediate((char *)actual + offset, value);
	if (memcmp(actual, expected, sizeof(actual))) {
		fprintf(stderr, "number mismatch: %" PRIx64 "\n", value);
		_exit(11);
	}
	++checked;
}

int main(void)
{
	for (uint64_t value = 0; value < 65536; ++value)
		check_number(value);
	for (unsigned bit = 0; bit < 64; ++bit)
		for (uint64_t delta = 0; delta < 4; ++delta) {
			check_number((UINT64_C(1) << bit) + delta);
			check_number((UINT64_C(1) << bit) - delta);
		}
	uint64_t state = UINT64_C(0x79239d481ac604be);
	for (unsigned i = 0; i < 1048576; ++i) {
		state ^= state << 13;
		state ^= state >> 7;
		state ^= state << 17;
		check_number(state);
	}
	const size_t page = (size_t)sysconf(_SC_PAGESIZE);
	unsigned char *mapping = mmap(NULL, page * 2, PROT_READ | PROT_WRITE,
				      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED || mprotect(mapping + page, page, PROT_NONE))
		return 12;
	for (unsigned digits = 1; digits <= 16; ++digits) {
		const uint64_t value = digits == 16 ? UINT64_MAX :
			(UINT64_C(1) << (digits * 4)) - 1;
		char expected[24];
		const int length = snprintf(expected, sizeof(expected), "0x%" PRIx64, value);
		char *out = (char *)mapping + page - length;
		writeUnsignedImmediate(out, value);
		if (memcmp(out, expected, (size_t)length))
			return 13;
	}
	if (munmap(mapping, page * 2))
		return 14;
	printf("equal independent numeric spellings and canaries for %" PRIu64
	       " values; 16 page-ended output extents\n", checked);
	return 0;
}
