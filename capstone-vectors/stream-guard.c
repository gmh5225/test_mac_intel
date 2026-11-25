#include "cs_priv.h"
#include "MathExtras.h"
#include "SStream.h"
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "reference.c"
#include "hex.c"

struct trace {
	char fmt[40];
	uint64_t arg;
	size_t capacity;
	unsigned calls;
};
static struct trace seen;
static unsigned policy;
static unsigned cases;

static int hooked(char *dst, size_t cap, const char *fmt, va_list args)
{
	va_list copy;
	va_copy(copy, args);
	seen.arg = va_arg(copy, uint64_t);
	va_end(copy);
	snprintf(seen.fmt, sizeof(seen.fmt), "%s", fmt);
	seen.capacity = cap;
	++seen.calls;
	if (policy == 2)
		return -1;
	if (policy == 3)
		return snprintf(dst, cap, "<value>");
	return vsnprintf(dst, cap, fmt, args);
}

static void check(uint64_t value, bool negative)
{
	const unsigned positions[] = {0, 7, 491, 492, 493, 500, 509, 510, 511, 512, 513};
	for (unsigned i = 0; i < sizeof(positions) / sizeof(*positions); ++i)
		for (unsigned flags = 0; flags < 8; ++flags)
			for (policy = 0; policy < 4; ++policy) {
				SStream before, after;
				memset(&before, 0x5a, sizeof(before));
				before.index = positions[i];
				if (before.index < sizeof(before.buffer))
					before.buffer[before.index] = '\0';
				before.is_closed = (flags & 1) != 0;
				before.markup_stream = (flags & 2) != 0;
				before.prefixed_by_markup = (flags & 4) != 0;
				before.unsigned_num = false;
				memcpy(&after, &before, sizeof(after));
				cs_vsnprintf = policy ? hooked : cs_default_vsnprintf;
				memset(&seen, 0, sizeof(seen));
				reference_hex(&before, value, negative);
				struct trace expected = seen;
				memset(&seen, 0, sizeof(seen));
				tested_hex(&after, value, negative);
				if (memcmp(&before, &after, sizeof(after)) ||
				    memcmp(&seen, &expected, sizeof(seen))) {
					fprintf(stderr, "value=%" PRIx64 " neg=%u offset=%zu flags=%u callback=%u\n",
						value, negative, (size_t)positions[i], flags, policy);
					abort();
				}
				++cases;
			}
}

int main(void)
{
	check(0, false);
	for (unsigned shift = 0; shift < 64; shift += 4)
		for (uint64_t first = 1; first <= 15; ++first) {
			const uint64_t small = first << shift;
			const uint64_t large = small | ((UINT64_C(1) << shift) - 1);
			check(small, false);
			check(large, false);
			{
				check(small, true);
				check(large, true);
			}
		}
	uint64_t random = UINT64_C(8672491980167);
	for (unsigned i = 0; i < 2048; ++i) {
		random = random * UINT64_C(6364136223846793005) + 1;
		check(random, false);
		check(random, true);
	}
	cs_vsnprintf = cs_default_vsnprintf;
	printf("%u\n", cases);
	return 0;
}
