#include "SStream.h"
#include <inttypes.h>
#include <stdio.h>
static uint64_t calls, indented;
void __real_SStream_trimls(SStream *);
void __wrap_SStream_trimls(SStream *stream)
{
    ++calls;
    indented += stream->buffer[0] == ' ' || stream->buffer[0] == '\t';
    __real_SStream_trimls(stream);
}
__attribute__((destructor))
static void report(void)
{
    fprintf(stderr, "%" PRIu64 " %" PRIu64 "\n", calls, indented);
}
