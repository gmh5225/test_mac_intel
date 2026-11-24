#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include "cs_priv.h"
#include "utils.h"
#include "arch/X86/X86UnsignedImmediate.h"

static unsigned long long checks;
static int check(uint64_t value)
{
	char expect[64], actual[64], text[24];
	for (unsigned offset = 1; offset < 12; offset += 5) {
		memset(actual, 0xa5, sizeof(actual));
		memset(expect, 0xa5, sizeof(expect));
		int n = value < 10 ? snprintf(text, sizeof(text), "%" PRIu64, value)
				   : snprintf(text, sizeof(text), "0x%" PRIx64, value);
		memcpy(expect + offset, text, n);
		char *end = writeUnsignedImmediate(actual + offset, value);
		if (end != actual + offset + n || memcmp(actual, expect, sizeof(actual))) {
			fprintf(stderr, "value=%" PRIx64 " offset=%u\n",value,offset);
			return 1;
		}
		++checks;
	}
	return 0;
}
int main(void)
{
	for (uint64_t v = 0; v <= UINT16_MAX; ++v)
		if (check(v)) return 1;
	for (unsigned shift = 0; shift < 64; ++shift)
		for (uint64_t byte = 0; byte < 256; ++byte) {
			uint64_t word = byte << shift;
			if (check(word) || check(word-1) || check(word+1) || check(~word)) return 1;
		}
	uint64_t x = 1442695040888963407ULL;
	for (unsigned i = 0; i < 400000; ++i) {
		x = x*6364136223846793005ULL+1442695040888963407ULL;
		if (check(x)) return 1;
	}
	printf("%llu\n", checks);
}
