#include "arch/X86/X86ATTInstPrinter.c"

static unsigned policy, calls;
static uint64_t trace;
static int observed(char *out, size_t n, const char *fmt, va_list ap)
{
	va_list copy;
	va_copy(copy, ap);
	unsigned value = (unsigned)va_arg(copy, int);
	va_end(copy);
	trace = n * 127 + value;
	for (const char *p = fmt; *p; ++p)
		trace = trace * 131 + (unsigned char)*p;
	++calls;
	if (policy == 2)
		return -1;
	if (policy == 3) {
		if (n) {
			memset(out, 'q', n - 1);
			out[n - 1] = '\0';
		}
		return (int)n + 2;
	}
	return vsnprintf(out, n, fmt, ap);
}
int main(void)
{
	cs_vsnprintf_t normal = cs_vsnprintf;
	uint64_t states = 0, callbacks = 0;
	for (unsigned value = 0; value < 256; ++value) for (policy = 0; policy < 4; ++policy) {
		cs_vsnprintf = policy ? observed : normal;
		for (unsigned flags = 0; flags < 16; ++flags) for (unsigned i = 0; i < SSTREAM_BUF_LEN + 3; ++i) {
			SStream ref, got;
			memset(&ref, 0xa5, sizeof(ref));
			ref.is_closed = !!(flags & 1); ref.markup_stream = !!(flags & 2);
			ref.prefixed_by_markup = !!(flags & 4); ref.unsigned_num = !!(flags & 8);
			ref.index = i == SSTREAM_BUF_LEN + 2 ? SIZE_MAX : i;
			if (ref.index < SSTREAM_BUF_LEN) ref.buffer[ref.index] = 0;
			got = ref; calls = 0; trace = 0;
			if (value > HEX_THRESHOLD) SStream_concat(&ref, "$0x%x", (uint8_t)value);
			else SStream_concat(&ref, "$%" PRIu8, (uint8_t)value);
			unsigned expected = calls;
			uint64_t expected_trace = trace;
			calls = 0; trace = 0; printUnsignedByte(&got, (uint8_t)value);
			if (memcmp(&ref, &got, sizeof(ref)) || calls != expected || trace != expected_trace) {
				fprintf(stderr, "value=%u policy=%u flags=%u index=%u\n",value,policy,flags,i);
				return 2;
			}
			++states; callbacks += calls;
		}
	}
	cs_vsnprintf = normal;
	printf("{\"states\":%llu,\"callbacks\":%llu}\n", (unsigned long long)states,(unsigned long long)callbacks);
	return 0;
}
