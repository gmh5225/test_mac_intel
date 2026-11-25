static size_t SStream_remaining(SStream *ss)
{
	assert(ss);
	if (ss->index >= SSTREAM_BUF_LEN) {
		ss->index = SSTREAM_BUF_LEN - 1;
		ss->buffer[ss->index] = '\0';
		return 0;
	}
	return SSTREAM_BUF_LEN - ss->index - 1;
}

static void SStream_concat_raw(SStream *ss, const char *s, size_t len)
{
	size_t remaining = SStream_remaining(ss);
	if (len > remaining) {
		len = remaining;
	}
	if (len > 0) {
		memcpy(ss->buffer + ss->index, s, len);
		ss->index += len;
	}
	ss->buffer[ss->index] = '\0';
}

static void SStream_concat1_raw(SStream *ss, char c)
{
	if (SStream_remaining(ss) == 0) {
		return;
	}
	ss->buffer[ss->index] = c;
	ss->index++;
	ss->buffer[ss->index] = '\0';
}

static void SStream_close_markup(SStream *ss)
{
	if (ss->markup_stream && ss->prefixed_by_markup) {
		SStream_concat1_raw(ss, '>');
	}
}
static void reference_hex(SStream *ss, uint64_t value, bool negative)
{
#if !defined(CAPSTONE_DIET) && defined(CAPSTONE_USE_SYS_DYN_MEM) && \
	!defined(CAPSTONE_HAS_OSXKERNEL) && !defined(_KERNEL_MODE) && \
	!defined(_WIN32_WCE)
	// CS_OPT_MEM may install a formatter with its own output/error behavior.
	if (cs_vsnprintf == cs_default_vsnprintf) {
		assert(ss);
		SSTREAM_RETURN_IF_CLOSED(ss);
		char buffer[19]; // sign, 0x, and up to 16 hexadecimal digits
		char *end = buffer + sizeof(buffer);
		char *p = end;
		do {
			*--p = "0123456789abcdef"[value & 15];
			value >>= 4;
		} while (value);
		*--p = 'x';
		*--p = '0';
		if (negative)
			*--p = '-';
		SStream_concat_raw(ss, p, (size_t)(end - p));
		SStream_close_markup(ss);
		return;
	}
#endif
	SStream_concat(ss, negative ? "-0x%" PRIx64 : "0x%" PRIx64, value);
}

