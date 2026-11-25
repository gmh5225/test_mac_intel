static void printAliasMnemonic(SStream *OS, const char *name)
{
#if defined(CAPSTONE_USE_SYS_DYN_MEM) && !defined(CAPSTONE_HAS_OSXKERNEL) && \
	!defined(_KERNEL_MODE) && !defined(_WIN32_WCE)
	if (cs_vsnprintf == cs_default_vsnprintf && !OS->is_closed &&
	    !OS->markup_stream && OS->index < SSTREAM_BUF_LEN - 1) {
		char *out = OS->buffer + OS->index;
		char *end = OS->buffer + SSTREAM_BUF_LEN - 1;
		*out++ = '\t';
		while (out != end && *name)
			*out++ = *name++;
		if (out != end)
			*out++ = '\t';
		*out = '\0';
		OS->index = (size_t)(out - OS->buffer);
		return;
	}
#endif
	SStream_concat2(OS, "\t", name);
	SStream_concat0(OS, "\t");
}
#define MEASURE_WRITE(ss,s) printAliasMnemonic((ss),(s))
