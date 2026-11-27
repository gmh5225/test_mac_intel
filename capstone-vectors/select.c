#include "SStream.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>

typedef void (*trim_fn)(SStream *);
void benchTrim_shipping(SStream *);
void benchTrim_first(SStream *);
void benchTrim_outlined(SStream *);
void benchTrim_printable(SStream *);
void benchTrim_control(SStream *);

static trim_fn selected;
#ifdef COUNT_CALLS
static uint64_t calls, horizontal, printable;
__attribute__((destructor)) static void report(void)
{
    fprintf(stderr, "%" PRIu64 " %" PRIu64 " %" PRIu64 "\n", calls, horizontal, printable);
}
#endif

__attribute__((constructor)) static void choose(void)
{
    static const trim_fn variants[] = {
        benchTrim_shipping, benchTrim_first, benchTrim_outlined,
        benchTrim_printable, benchTrim_control, benchTrim_shipping
    };
    const char *value = getenv("CS_BENCH_TRIM");
    if (!value || value[0] < '0' || value[0] > '5' || value[1])
        abort();
    selected = variants[value[0] - '0'];
}

void __wrap_SStream_trimls(SStream *stream)
{
#ifdef COUNT_CALLS
    ++calls;
    horizontal += stream->buffer[0] == ' ' || stream->buffer[0] == '\t';
    printable += (unsigned char)stream->buffer[0] > ' ';
#endif
    selected(stream);
}
