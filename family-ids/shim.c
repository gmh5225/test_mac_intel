#include "SStream.h"
#include "cs_priv.h"
#include <stdio.h>
#include <string.h>

/* Expose only the selected static archive's stream implementation. */
void stream_hex_probe(SStream *out, uint64_t value, bool negative)
{
    SStream_concat_hex64(out, value, negative);
}

static unsigned custom_mode;
static int alternate(char *buffer, size_t size, const char *format, va_list arguments)
{
    if(custom_mode==1) return vsnprintf(buffer,size,format,arguments);
    if(size) buffer[0]=0;
    if(custom_mode==2) return -1;
    if(size>1) memcpy(buffer,"q",2);
    return 27;
}
void stream_select_formatter(unsigned mode)
{
    custom_mode=mode;
    cs_vsnprintf=mode?alternate:cs_default_vsnprintf;
}
