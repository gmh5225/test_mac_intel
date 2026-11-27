#include "SStream.h"
#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    unsigned long count = 0;
    for (size_t leading = 0; leading < SSTREAM_BUF_LEN; ++leading) {
        const size_t ends[] = { leading, leading < 506 ? leading + 5 : 511, 511 };
        for (unsigned kind = 0; kind < 3; ++kind) {
            size_t end = ends[kind];
            size_t indices[] = { 0, 1, leading, end, end + 1, 511, 512, 513, SIZE_MAX };
            for (unsigned flags = 0; flags < 16; ++flags) {
                for (unsigned i = 0; i < sizeof(indices) / sizeof(indices[0]); ++i) {
                    SStream actual = { 0 }, before, expected;
                    for (size_t j = 0; j < sizeof(actual.buffer); ++j)
                        actual.buffer[j] = j < leading ? ((j + flags) & 1 ? '\t' : ' ') :
                                           j < end ? (char)('a' + j % 26) :
                                           (char)(0x40 + (j * 13) % 63);
                    actual.buffer[end] = 0;
                    actual.index = indices[i];
                    actual.is_closed = (flags & 1) != 0;
                    actual.markup_stream = (flags & 2) != 0;
                    actual.prefixed_by_markup = (flags & 4) != 0;
                    actual.unsigned_num = (flags & 8) != 0;
                    memcpy(&before, &actual, sizeof(actual));
                    memcpy(&expected, &actual, sizeof(actual));
                    if (leading) {
                        for (size_t j = 0; j < sizeof(actual.buffer) - leading; ++j)
                            expected.buffer[j] = before.buffer[j + leading];
                        if (expected.index < end)
                            expected.index = end;
                        expected.index -= leading;
                    }
                    SStream_trimls(&actual);
                    if (memcmp(&actual, &expected, sizeof(actual))) {
                        fprintf(stderr, "prefix=%zu end=%zu cursor=%zu flags=%u\n",
                                leading, end, indices[i], flags);
                        return 1;
                    }
                    ++count;
                }
            }
        }
    }
    printf("%lu\n", count);
    return 0;
}
