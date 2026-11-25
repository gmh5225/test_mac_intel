static void printAliasMnemonic(SStream *OS, const char *name)
{
#if defined(CAPSTONE_USE_SYS_DYN_MEM) && !defined(CAPSTONE_HAS_OSXKERNEL) && \
	!defined(_KERNEL_MODE) && !defined(_WIN32_WCE)
	/* Ordinary output writes the tab, alias and operand separator together.
	 * Markup and user formatters observe their original append boundaries. */
	if (cs_vsnprintf == cs_default_vsnprintf && !OS->is_closed &&
	    !OS->markup_stream && OS->index < SSTREAM_BUF_LEN - 2) {
		const size_t NameLen = strlen(name);
		if (NameLen < SSTREAM_BUF_LEN - 2 - OS->index) {
			char *out = OS->buffer + OS->index;
			*out++ = '\t';
			memcpy(out, name, NameLen);
			memcpy(out + NameLen, "\t", 2);
			OS->index += NameLen + 2;
			return;
		}
	}
#endif
	SStream_concat2(OS, "\t", name);
	SStream_concat0(OS, "\t");
}
#define MEASURE_WRITE(ss,s) printAliasMnemonic((ss),(s))
