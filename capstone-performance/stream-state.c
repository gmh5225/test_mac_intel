#include "SStream.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void record(const SStream *s)
{
	const uint64_t length = s->index;
	const unsigned char flags[] = { s->is_closed, s->markup_stream,
					s->prefixed_by_markup, s->unsigned_num };
	fwrite(&length, sizeof(length), 1, stdout);
	fwrite(flags, sizeof(flags), 1, stdout);
	fwrite(s->buffer, sizeof(s->buffer), 1, stdout);
}

int main(int argc, char **argv)
{
	if (argc > 1) {
		printf("%zu %zu %zu %zu\n", sizeof(SStream), offsetof(SStream, buffer),
		       offsetof(SStream, index), offsetof(SStream, is_closed));
		return 0;
	}
	for (unsigned flags = 0; flags < 16; flags++) {
		for (unsigned n = 0; n < SSTREAM_BUF_LEN; ++n) {
			SStream s;
			memset(&s, 0xa5, sizeof(s));
			SStream_Init(&s);
			memset(s.buffer, 'x', n);
			s.buffer[n] = 0;
			s.index = n;
			s.is_closed = (flags & 1) != 0;
			s.markup_stream = (flags & 2) != 0;
			s.prefixed_by_markup = (flags & 4) != 0;
			s.unsigned_num = (flags & 8) != 0;
			SStream_concat0_small(&s, "xmm10", 5);
			record(&s);
			SStream_concat_hex64(&s, UINT64_C(0xfedcba9876543210), true);
			record(&s);
			SStream_concat1(&s, ']');
			record(&s);
		}
	}
	return ferror(stdout) ? 1 : 0;
}
