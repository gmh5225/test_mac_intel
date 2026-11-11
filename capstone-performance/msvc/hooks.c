#include <stdarg.h>
#include <stdio.h>
#include "cs_priv.h"

unsigned stream_hooks(void);
unsigned mapping_hooks(void);

static int wrapper(char *out, size_t length, const char *format, va_list args)
{
	return vsnprintf(out, length, format, args);
}

int main(void)
{
	cs_vsnprintf_t initial = cs_vsnprintf;
	unsigned initial_stream = stream_hooks(), initial_mapping = mapping_hooks();
	cs_vsnprintf = wrapper;
	unsigned custom = stream_hooks();
	cs_vsnprintf = initial;
	printf("{\"stream\":%u,\"mapping\":%u,\"custom\":%u,\"restored\":%u}\n",
	       initial_stream, initial_mapping, custom, stream_hooks());
	return 0;
}
