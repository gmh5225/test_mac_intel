#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*bench_reader_fn)(struct InternalInstruction *);
static bench_reader_fn selected_reader;
#ifdef READER_COUNTS
static uint64_t visits, shift_rows, other_three;
static FILE *capture_stream;
__attribute__((destructor)) static void report_reader_counts(void)
{
    if (capture_stream && fclose(capture_stream))
        abort();
    fprintf(stderr, "%" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
            visits, shift_rows, other_three);
}
#endif

__attribute__((constructor)) static void choose_reader(void)
{
    static const bench_reader_fn implementations[] = {
        benchReader_shipping, benchReader_shift, benchReader_triple,
        benchReader_pair, benchReader_both, benchReader_shipping
    };
    const char *v = getenv("CS_BENCH_READER");
    if (!v) v = "0";
    if (*v < '0' || *v > '5' || v[1])
        abort();
    selected_reader = implementations[*v - '0'];
#ifdef READER_COUNTS
    const char *path = getenv("CS_BENCH_READ_TRACE");
    if (path && !(capture_stream = fopen(path, "wb")))
        abort();
#endif
}

static int readOperands(struct InternalInstruction *insn)
{
#ifdef READER_COUNTS
    unsigned set = insn->spec->operands;
    ++visits;
    shift_rows += set >= 196 && set <= 199;
    other_three += (set >= 44 && set <= 47) || (set >= 101 && set <= 106) ||
                   (set >= 192 && set <= 195);
    if (capture_stream) {
        uint8_t row[20] = { (uint8_t)set, (uint8_t)(set >> 8) };
        row[2] = insn->mode == MODE_64BIT ? 64 : insn->mode == MODE_32BIT ? 32 : 16;
        row[3] = (uint8_t)(insn->codeSize < 15 ? insn->codeSize : 15);
        memcpy(row+4, insn->code, row[3]);
        if (fwrite(row, sizeof(row), 1, capture_stream) != 1) abort();
    }
#endif
    return selected_reader(insn);
}
