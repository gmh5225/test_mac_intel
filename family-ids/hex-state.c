#include "SStream.h"
#include <dlfcn.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef void (*writer)(SStream *, uint64_t, bool);
static writer old_writer, new_writer;
static uint64_t checks;

static void check(uint64_t value, unsigned negative, unsigned flags, size_t index)
{
    SStream a, b;
    memset(&a, 0xa5, sizeof(a));
    a.index = index;
    a.is_closed = !!(flags & 1);
    a.markup_stream = !!(flags & 2);
    a.prefixed_by_markup = !!(flags & 4);
    a.unsigned_num = !!(flags & 8);
    memcpy(&b, &a, sizeof(a));
    old_writer(&a, value, negative);
    new_writer(&b, value, negative);
    if (memcmp(&a, &b, sizeof(a))) {
        fprintf(stderr, "hex state differs value=%" PRIx64 " sign=%u flags=%u index=%zu\n", value, negative, flags, index);
        exit(1);
    }
    ++checks;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    void *old_lib = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
    void *new_lib = dlopen(argv[2], RTLD_NOW | RTLD_LOCAL);
    if (!old_lib || !new_lib) return 3;
    old_writer = (writer)dlsym(old_lib, "stream_hex_probe");
    new_writer = (writer)dlsym(new_lib, "stream_hex_probe");
    if (!old_writer || !new_writer) return 4;
    const size_t indices[] = {0, 1, 7, SSTREAM_BUF_LEN - 21,
        SSTREAM_BUF_LEN - 7, SSTREAM_BUF_LEN - 4, SSTREAM_BUF_LEN - 2,
        SSTREAM_BUF_LEN - 1, SSTREAM_BUF_LEN, SIZE_MAX};
    void (*oc)(unsigned)=(void (*)(unsigned))dlsym(old_lib,"stream_select_formatter");
    void (*nc)(unsigned)=(void (*)(unsigned))dlsym(new_lib,"stream_select_formatter");
    if (!oc || !nc) return 5;
    for (unsigned cb=1; cb<=3; ++cb) {
        oc(cb); nc(cb);
        for(unsigned sign=0; sign<2; ++sign)
            for(unsigned flags=0; flags<16; ++flags)
                for(size_t i=0; i<sizeof(indices)/sizeof(indices[0]); ++i)
                    for(unsigned n=0; n<64; ++n) check(UINT64_C(1)<<n,sign,flags,indices[i]);
    }
    oc(0); nc(0);
    for (uint64_t value = 0; value <= 65535; ++value)
        for (unsigned negative = 0; negative < 2; ++negative)
            for (unsigned flags = 0; flags < 16; ++flags)
                for (size_t i = 0; i < sizeof(indices)/sizeof(indices[0]); ++i)
                    check(value, negative, flags, indices[i]);
    for (unsigned bits = 0; bits < 64; ++bits) {
        uint64_t power = UINT64_C(1) << bits;
        for (int delta = -1; delta <= 1; ++delta)
            for (unsigned negative = 0; negative < 2; ++negative)
                for (unsigned flags = 0; flags < 16; ++flags)
                    for (size_t index = 0; index <= SSTREAM_BUF_LEN; ++index)
                        check(power + delta, negative, flags, index);
    }
    uint64_t rng = UINT64_C(0x1927384655abcdef);
    for (unsigned i = 0; i < 20000; ++i) {
        rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17;
        for (unsigned negative = 0; negative < 2; ++negative)
            for (unsigned flags = 0; flags < 16; ++flags)
                check(rng, negative, flags, indices[i % (sizeof(indices)/sizeof(indices[0]))]);
    }
    printf("%" PRIu64 " complete hexadecimal stream states matched\n", checks);
    dlclose(new_lib); dlclose(old_lib);
    return 0;
}
