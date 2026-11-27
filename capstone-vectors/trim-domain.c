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
    for (unsigned first = 0; first <= UINT8_MAX; ++first) {
        for (unsigned flags = 0; flags < 16; ++flags) {
            SStream actual = { 0 }, expected;
            memset(actual.buffer, 0x9b, sizeof(actual.buffer));
            actual.buffer[0] = (char)first;
            actual.buffer[1] = 'A';
            actual.buffer[2] = 0;
            actual.index = flags & 4 ? SIZE_MAX : (flags & 3);
            actual.is_closed = (flags & 1) != 0;
            actual.markup_stream = (flags & 2) != 0;
            actual.prefixed_by_markup = (flags & 4) != 0;
            actual.unsigned_num = (flags & 8) != 0;
            memcpy(&expected, &actual, sizeof(actual));
            if (first == ' ' || first == '\t') {
                memmove(expected.buffer, expected.buffer + 1, sizeof(expected.buffer) - 1);
                if (expected.index < 2) expected.index = 2;
                --expected.index;
            }
            SStream_trimls(&actual);
            if (memcmp(&actual, &expected, sizeof(actual))) return 2;
            ++count;
        }
    }
    printf("%lu\n", count);
    return 0;
}
