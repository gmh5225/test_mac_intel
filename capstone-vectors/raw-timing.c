#define _POSIX_C_SOURCE 200809L
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "arch/X86/X86DisassemblerDecoder.h"

static uint64_t nanos(clockid_t clock)
{
    struct timespec ts;
    if (clock_gettime(clock, &ts)) abort();
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + ts.tv_nsec;
}

int main(int argc, char **argv)
{
    if (argc != 3) return 2;
    FILE *input = fopen(argv[1], "rb");
    if (!input || fseek(input, 0, SEEK_END)) return 3;
    long size = ftell(input);
    if (size <= 0 || size % 20 || fseek(input, 0, SEEK_SET)) return 4;
    uint8_t *buf = malloc((size_t)size);
    if (!buf || fread(buf, 1, (size_t)size, input) != (size_t)size || fclose(input)) return 5;
    unsigned repeats = (unsigned)strtoul(argv[2], NULL, 10);
    uint64_t start_cpu = nanos(CLOCK_PROCESS_CPUTIME_ID), start_wall = nanos(CLOCK_MONOTONIC);
    uint64_t rejected=0, mismatched=0, sum=0;
    for (unsigned i=0; i<repeats; ++i) {
        for (long offset=0; offset<size; offset+=20) {
            const uint8_t *r=buf+offset;
            InternalInstruction record = {0};
            cs_mode mode=r[2]==64 ? CS_MODE_64 : r[2]==32 ? CS_MODE_32 : CS_MODE_16;
            int status=decodeInstruction(&record,r+4,r[3],mode);
            unsigned set=(unsigned)r[0]+((unsigned)r[1]<<8);
            rejected += status != 0;
            mismatched += !record.spec || record.spec->operands != set;
            sum += record.instructionID + record.readerCursor + record.reg + record.eaBase +
                   record.immediates[0] + record.displacement;
        }
    }
    uint64_t cpu=nanos(CLOCK_PROCESS_CPUTIME_ID)-start_cpu,wall=nanos(CLOCK_MONOTONIC)-start_wall;
    printf("%" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
           cpu,wall,(uint64_t)(size/20)*repeats,rejected,mismatched,sum);
    free(buf);
    return 0;
}
