#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#define CAPSTONE_HAS_X86
#include "helper.cfrag"

static int compare(const unsigned char input[8], uint64_t *hits)
{
    char out[32], ref[32] = {0};
    memset(out, 0, sizeof(out));
    size_t end = 0, expected = 0;
    while (expected < 8 && input[expected] != 0 && input[expected] != ' ' && input[expected] != '\t') {
        ref[expected] = input[expected] == '|' ? ' ' : (char)input[expected];
        ++expected;
    }
    if (!copy_short_x86_mnemonic(out, (const char *)input, &end)) return 0;
    ++*hits;
    return expected != end || memcmp(out, ref, sizeof(out));
}
int main(void)
{
    uint64_t hits = 0, count = 0, random = UINT64_C(0x39028acfeea9753d);
    unsigned char input[8];
    for (unsigned i=0; i<8; ++i) for (unsigned j=0; j<8; ++j) if (i!=j)
        for (unsigned a=0; a<256; ++a) for (unsigned b=0; b<256; ++b) {
            memset(input, 'a', 8); input[i]=a; input[j]=b;
            if (compare(input,&hits)) return 1;
            ++count;
        }
    for(unsigned i=0; i<1000000; ++i) {
        random ^= random<<13; random ^= random>>7; random ^= random<<17;
        memcpy(input, &random, sizeof(input));
        if (compare(input,&hits)) return 1;
        ++count;
    }
    printf("%llu cases, %llu exact short paths\n",(unsigned long long)count,(unsigned long long)hits);
    return hits==0;
}
