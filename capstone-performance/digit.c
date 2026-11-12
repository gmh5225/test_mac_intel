#define CAPSTONE_SSTREAM_PRECHECKED
#include "SStream.h"
#include "utils.h"
#include "helper.cfrag"

int main(void)
{
	unsigned cases = 0;
	for (size_t off = 0; off < SSTREAM_BUF_LEN; ++off) {
		for (unsigned sign = 0; sign < 2; ++sign) {
			if (off + 1 + sign >= SSTREAM_BUF_LEN)
				continue;
			for (uint64_t value = 0; value < 10; ++value) {
				for (int seed = 0; seed < 2; ++seed) {
					SStream old, candidate;
					memset(&old, seed ? 0x5a : 0xa5, sizeof(old));
					old.index = off;
					old.buffer[off] = 0;
					old.is_closed = old.markup_stream = old.prefixed_by_markup = false;
					old.unsigned_num = seed != 0;
					memcpy(&candidate, &old, sizeof(old));
					SStream_concat_dec64(&old, value, sign != 0);
					printDecimalDigit(&candidate, value, sign != 0);
					if (memcmp(&candidate, &old, sizeof(old)) != 0)
						return 1;
					++cases;
				}
			}
		}
	}
	printf("Compared %u complete streams\n", cases);
	return !cases;
}
