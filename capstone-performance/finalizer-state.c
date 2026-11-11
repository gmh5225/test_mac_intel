#include "cs.c"
static inline void reference_fill_insn(struct cs_struct *handle, cs_insn *insn,
			     SStream *OS, MCInst *mci,
			     PostPrinter_t postprinter, const uint8_t *code,
			     bool stream_length_valid)
{
	SStream_trimls(OS);
	// Copy only decoded instruction bytes before the postprinter observes them.
	uint16_t copy_size = copy_insn_bytes(insn, code, false);
	insn->op_str[0] = '\0';
	insn->size = copy_size;

	// alias instruction might have ID saved in OpcodePub
	if (MCInst_getOpcodePub(mci))
		insn->id = MCInst_getOpcodePub(mci);

	// post printer handles some corner cases (hacky)
	if (postprinter)
		postprinter((csh)handle, insn, OS, mci);

#ifndef CAPSTONE_DIET
	memset(insn->mnemonic, '\0', sizeof(insn->mnemonic));
	memset(insn->op_str, '\0', sizeof(insn->op_str));
	size_t off = 0;
	while (off < sizeof(insn->mnemonic) - 1 && OS->buffer[off] &&
	       OS->buffer[off] != ' ' && OS->buffer[off] != '\t') {
		char c = OS->buffer[off];
		insn->mnemonic[off] = c == '|' ? ' ' : c;
		off++;
	}
	while (OS->buffer[off] && OS->buffer[off] != ' ' &&
	       OS->buffer[off] != '\t')
		off++;
	while (OS->buffer[off] == ' ' || OS->buffer[off] == '\t')
		off++;
	const char *operands = OS->buffer + off;
	if (stream_length_valid) {
		/* The private x86 stream's index is its terminating NUL. */
		const size_t length =
			MIN(OS->index - off, sizeof(insn->op_str) - 1);
		if (length > 32) {
			memcpy(insn->op_str, operands, length);
		} else if (length >= 16) {
			memcpy(insn->op_str, operands, 16);
			memcpy(insn->op_str + length - 16,
			       operands + length - 16, 16);
		} else if (length >= 8) {
			memcpy(insn->op_str, operands, 8);
			memcpy(insn->op_str + length - 8, operands + length - 8,
			       8);
		} else if (length >= 4) {
			memcpy(insn->op_str, operands, 4);
			memcpy(insn->op_str + length - 4, operands + length - 4,
			       4);
		} else if (length >= 2) {
			memcpy(insn->op_str, operands, 2);
			memcpy(insn->op_str + length - 2, operands + length - 2,
			       2);
		} else if (length) {
			insn->op_str[0] = operands[0];
		}
	} else {
		for (off = 0; operands[off] && off < sizeof(insn->op_str) - 1;
		     off++)
			insn->op_str[off] = operands[off];
	}

	// we might have customized mnemonic
	if (handle->mnem_list) {
		struct insn_mnem *tmp = handle->mnem_list;
		while (tmp) {
			if (tmp->insn.id == insn->id) {
				char str[CS_MNEMONIC_SIZE] = { 0 };

				if (!str_replace(str, insn->mnemonic,
						 cs_insn_name((csh)handle,
							      insn->id),
						 tmp->insn.mnemonic)) {
					// copy result to mnemonic
					CS_ASSERT_RET(sizeof(insn->mnemonic) ==
						      sizeof(str));
					(void)memcpy(insn->mnemonic, str,
						     sizeof(insn->mnemonic));
					insn->mnemonic[sizeof(insn->mnemonic) -
						       1] = '\0';
				}

				break;
			}
			tmp = tmp->next;
		}
	}
#endif
}
/* Artifact-only differential driver. Included after cs.c and the frozen
 * reference_fill_insn. This file does not replace either implementation. */

#include <inttypes.h>
#include <stdlib.h>

typedef struct {
  uint64_t key;
  unsigned post_mode;
  unsigned custom_mode;
  unsigned canonical;
  unsigned replacement_length;
  bool detail;
} ProbeOptions;

typedef struct {
  ProbeOptions options;
  const char *raw;
} ProbeContext;

typedef struct {
  unsigned char before[32];
  cs_insn insn;
  unsigned char after[32];
} ProbeInsn;

typedef struct {
  unsigned char before[32];
  SStream stream;
  unsigned char after[32];
} ProbeStream;

static uint64_t probe_fast_comparisons;
static int probe_formatter(char *out, size_t size, const char *format, va_list args) {
  return vsnprintf(out, size, format, args);
}
static uint64_t probe_comparisons;
static uint64_t probe_post_comparisons;
static uint64_t probe_custom_comparisons;
static uint64_t probe_detail_comparisons;
static const char *probe_phase;

static const char *probe_insn_name(csh handle, unsigned int id) {
  static const char *const names[] = {
      "",
      "a",
      "abc",
      "lock abc",
      "0123456789012345678901234567890",
      "01234567890123456789012345678901",
      "012345678901234567890123456789012",
      "0123456789012345678901234567890123456789"};
  const cs_struct *h = (const cs_struct *)(uintptr_t)handle;
  const ProbeContext *context = h->printer_info;
  (void)id;
  return names[context->options.canonical % ARR_SIZE(names)];
}

static void probe_postprinter(csh handle, cs_insn *insn, SStream *stream,
                              MCInst *mci) {
  const cs_struct *h = (const cs_struct *)(uintptr_t)handle;
  const ProbeContext *context = h->printer_info;
  if (insn->op_str[0] != '\0') {
    fprintf(stderr, "postprinter observed uncleared op_str[0]\n");
    abort();
  }
  if (stream->buffer[0] == ' ' || stream->buffer[0] == '\t') {
    fprintf(stderr, "postprinter observed untrimmed input\n");
    abort();
  }
  /* Observe fields before final clearing, then overwrite them. */
  insn->alias_id ^= (unsigned char)insn->mnemonic[0];
  insn->address += stream->index;
  insn->bytes[23] ^= (unsigned char)stream->buffer[0];
  memset(insn->mnemonic, 0xb1, sizeof(insn->mnemonic));
  memset(insn->op_str, 0xb2, sizeof(insn->op_str));
  insn->id = 7 + context->options.key % 3;
  mci->popcode_adjust = (uint8_t)stream->buffer[0];
  if (insn->detail) {
    insn->detail->groups_count = 1;
    insn->detail->groups[0] = (uint8_t)context->options.key;
    insn->detail->regs_read_count = 1;
    insn->detail->regs_read[0] = (uint16_t)context->options.key;
  }
  switch (context->options.post_mode) {
  case 1: /* Observe only. */
    break;
  case 2: /* Restore untrimmed text without maintaining its length. */
    memcpy(stream->buffer, context->raw, sizeof(stream->buffer));
    stream->index = SIZE_MAX - (size_t)context->options.key;
    break;
  case 3: { /* Shorten the visible string, leaving index and tail stale. */
    size_t length = strlen(stream->buffer);
    stream->buffer[length / 2] = '\0';
    break;
  }
  case 4: { /* Extend the visible string without updating index. */
    size_t length = strlen(stream->buffer);
    if (length + sizeof(" |end") <= sizeof(stream->buffer))
      memcpy(stream->buffer + length, " |end", sizeof(" |end"));
    break;
  }
  case 5:
    stream->buffer[0] = '\0';
    stream->index = SIZE_MAX;
    break;
  default:
    abort();
  }
}

static void probe_check_bytes(const void *a, const void *b, size_t size,
                              const char *object, ProbeOptions options) {
  if (memcmp(a, b, size) == 0)
    return;
  const unsigned char *left = a, *right = b;
  size_t offset = 0;
  while (offset < size && left[offset] == right[offset])
    offset++;
  fprintf(stderr,
          "mismatch phase=%s case=%" PRIu64 " key=%" PRIu64
          " post=%u custom=%u canonical=%u replacement=%u object=%s"
          " offset=%zu reference=%02x candidate=%02x\n",
          probe_phase, probe_comparisons, options.key, options.post_mode,
          options.custom_mode, options.canonical, options.replacement_length,
          object, offset, left[offset], right[offset]);
  abort();
}

static void probe_case(const char input[SSTREAM_BUF_LEN],
                       ProbeOptions options) {
  ProbeInsn original, reference, candidate;
  ProbeStream stream_original, stream_reference, stream_candidate;
  cs_detail detail, detail_reference;
  MCInst mc_reference = {0}, mc_candidate = {0};
  cs_struct handle = {0};
  ProbeContext context = {options, input};
  struct insn_mnem names[4] = {0};
  uint8_t code[65];
  const unsigned char pattern = 17 + options.key % 191;
  memset(&original, pattern, sizeof(original));
  original.insn.id = 7 + options.key % 3;
  original.insn.size = (options.key >> 8) % sizeof(code);
  original.insn.is_alias = (options.key & 1) != 0;
  original.insn.usesAliasDetails = (options.key & 2) != 0;
  original.insn.illegal = (options.key & 4) != 0;
  original.insn.detail = options.detail ? &detail : NULL;
  memcpy(&reference, &original, sizeof(reference));
  memcpy(&candidate, &original, sizeof(candidate));
  memset(&stream_original, pattern, sizeof(stream_original));
  memcpy(stream_original.stream.buffer, input, SSTREAM_BUF_LEN);
  const size_t indexes[] = {0, 1, strlen(input), 511, 512, SIZE_MAX};
  stream_original.stream.index =
      indexes[(options.key >> 4) % ARR_SIZE(indexes)];
  stream_original.stream.is_closed = (options.key & 1) != 0;
  stream_original.stream.markup_stream = (options.key & 2) != 0;
  stream_original.stream.prefixed_by_markup = (options.key & 4) != 0;
  stream_original.stream.unsigned_num = (options.key & 8) != 0;
  memcpy(&stream_reference, &stream_original, sizeof(stream_reference));
  memcpy(&stream_candidate, &stream_original, sizeof(stream_candidate));
  for (size_t i = 0; i < sizeof(code); ++i)
    code[i] = (uint8_t)(i * 17 + options.key);
  handle.insn_name = probe_insn_name;
  handle.printer_info = &context;
  if (options.custom_mode) {
    for (size_t i = 0; i < ARR_SIZE(names); ++i) {
      names[i].insn.id = i ? 6 + i : 1000;
      if (options.custom_mode == 2)
        names[i].insn.id += 100;
      if (options.custom_mode == 3)
        names[i].insn.id = 7;
      for (unsigned j = 0; j < options.replacement_length; ++j)
        names[i].insn.mnemonic[j] = j % 5 == 0 ? '|' : (char)('A' + i);
      names[i].next = i + 1 < ARR_SIZE(names) ? &names[i + 1] : NULL;
    }
    handle.mnem_list = names;
  }
  mc_reference.csh = mc_candidate.csh = &handle;
  mc_reference.flat_insn = &reference.insn;
  mc_candidate.flat_insn = &candidate.insn;
  mc_reference.OpcodePub = mc_candidate.OpcodePub =
      (options.key & (UINT64_C(1) << 15)) ? 9 : 0;
  PostPrinter_t post = options.post_mode ? probe_postprinter : NULL;
  cs_vsnprintf = vsnprintf;
  if (!options.post_mode && !options.detail) {
    handle.arch = CS_ARCH_X86;
    post = X86_postprinter;
    if ((options.key & 1) == 0) {
      stream_reference.stream.index = stream_candidate.stream.index = strlen(input);
      ++probe_fast_comparisons;
    } else {
      cs_vsnprintf = probe_formatter;
    }
  }

  if (options.detail)
    memset(&detail, pattern, sizeof(detail));
  reference_fill_insn(&handle, &reference.insn, &stream_reference.stream,
                      &mc_reference, post, code, !options.post_mode && !options.detail && (options.key & 1) == 0);
  if (options.detail) {
    memcpy(&detail_reference, &detail, sizeof(detail));
    memset(&detail, pattern, sizeof(detail));
  }
  fill_insn(&handle, &candidate.insn, &stream_candidate.stream, &mc_candidate,
            post, code, !options.post_mode && !options.detail && (options.key & 1) == 0);
  probe_check_bytes(&reference, &candidate, sizeof(reference), "cs_insn+guards",
                    options);
  probe_check_bytes(post ? &stream_reference : &stream_original, &stream_candidate,
                    sizeof(stream_reference), "SStream+guards", options);
  if (options.detail)
    probe_check_bytes(&detail_reference, &detail, sizeof(detail), "cs_detail",
                      options);
  if (mc_reference.popcode_adjust != mc_candidate.popcode_adjust)
    abort();
  ++probe_comparisons;
  probe_post_comparisons += options.post_mode != 0;
  probe_custom_comparisons += options.custom_mode != 0;
  probe_detail_comparisons += options.detail;
}

static void probe_text(char out[SSTREAM_BUF_LEN], size_t leading,
                       size_t mnemonic, size_t separator, size_t operands) {
  memset(out, 0xd3, SSTREAM_BUF_LEN);
  size_t at = 0;
  for (size_t i = 0; i < leading; ++i)
    out[at++] = i % 2 ? '\t' : ' ';
  for (size_t i = 0; i < mnemonic; ++i)
    out[at++] = i % 7 == 0 ? '|' : (char)('a' + i % 23);
  for (size_t i = 0; i < separator; ++i)
    out[at++] = i % 2 ? ' ' : '\t';
  for (size_t i = 0; i < operands; ++i)
    out[at++] = i % 11 == 0 ? 'x' : "a| \t\n"[i % 5];
  assert(at < SSTREAM_BUF_LEN);
  out[at] = '\0';
}

int main(void) {
  char input[SSTREAM_BUF_LEN];
  ProbeOptions options = {0};
  probe_phase = "all-short-words";
  static const char alphabet[] = {'a', ' ', '\t', '|', '\n'};
  uint64_t words = 1;
  for (size_t length = 0; length <= 8; ++length) {
    for (uint64_t word = 0; word < words; ++word) {
      memset(input, 0xd3, sizeof(input));
      uint64_t value = word;
      for (size_t i = 0; i < length; ++i) {
        input[i] = alphabet[value % ARR_SIZE(alphabet)];
        value /= ARR_SIZE(alphabet);
      }
      input[length] = '\0';
      options.key = probe_comparisons;
      probe_case(input, options);
    }
    words *= ARR_SIZE(alphabet);
  }

  probe_phase = "all-token-lengths";
  const size_t leading_sizes[] = {0, 1, 2, 31};
  const size_t separator_sizes[] = {0, 1, 2, 31};
  for (size_t li = 0; li < ARR_SIZE(leading_sizes); ++li)
    for (size_t si = 0; si < ARR_SIZE(separator_sizes); ++si) {
      size_t leading = leading_sizes[li], separator = separator_sizes[si];
      for (size_t mnemonic = 0; mnemonic + leading + separator < 512;
           ++mnemonic)
        for (size_t operands = 0;
             operands + mnemonic + leading + separator < 512; ++operands) {
          probe_text(input, leading, mnemonic, separator, operands);
          options.key = probe_comparisons;
          probe_case(input, options);
        }
    }

  probe_phase = "all-leading-lengths-and-state-edges";
  const size_t edges[] = {0, 1, 2, 30, 31, 32, 158, 159, 160, 255, 510, 511};
  for (size_t leading = 0; leading < 512; ++leading)
    for (size_t ei = 0; ei < ARR_SIZE(edges); ++ei) {
      size_t mnemonic = edges[ei];
      if (leading + mnemonic >= 512)
        continue;
      size_t separator = leading + mnemonic < 511 ? 1 : 0;
      size_t operands = 511 - leading - mnemonic - separator;
      probe_text(input, leading, mnemonic, separator, operands);
      for (unsigned flags = 0; flags < 16; ++flags)
        for (unsigned index = 0; index < 6; ++index) {
          options.key = flags | ((uint64_t)index << 4) |
                        ((uint64_t)(leading % 65) << 8) |
                        ((uint64_t)(ei & 1) << 15);
          probe_case(input, options);
        }
    }

  probe_phase = "all-byte-values-at-boundaries";
  for (size_t ei = 0; ei < ARR_SIZE(edges); ++ei)
    for (unsigned byte = 0; byte < 256; ++byte) {
      probe_text(input, 0, 32, 1, 478);
      if (edges[ei] < 511)
        input[edges[ei]] = (char)byte;
      options.key = probe_comparisons;
      probe_case(input, options);
    }

  probe_phase = "postprinter-all-output-lengths";
  for (size_t length = 0; length < 512; ++length)
    for (size_t split = 0; split <= length; ++split) {
      size_t separator = split < length ? 1 : 0;
      probe_text(input, 0, split, separator, length - split - separator);
      for (unsigned post = 1; post < 6; ++post) {
        options.key = probe_comparisons;
        options.post_mode = post;
        probe_case(input, options);
      }
    }

  probe_phase = "postprinter-and-custom-mnemonics";
  for (size_t mi = 0; mi < ARR_SIZE(edges); ++mi)
    for (size_t oi = 0; oi < ARR_SIZE(edges); ++oi) {
      size_t mnemonic = edges[mi], operands = edges[oi];
      if (mnemonic + operands + 3 >= 512)
        continue;
      probe_text(input, 2, mnemonic, 1, operands);
      for (unsigned post = 0; post < 6; ++post)
        for (unsigned custom = 0; custom < 4; ++custom)
          for (unsigned canonical = 0; canonical < 8; ++canonical)
            for (unsigned replacement = 0; replacement < 32; ++replacement) {
              options.key = probe_comparisons;
              options.post_mode = post;
              options.custom_mode = custom;
              options.canonical = canonical;
              options.replacement_length = replacement;
              options.detail = true;
              probe_case(input, options);
            }
    }
  printf("{\"comparisons\":%" PRIu64 ",\"postprinter\":%" PRIu64
         ",\"custom_mnemonic\":%" PRIu64 ",\"detail\":%" PRIu64 "}\n",
         probe_comparisons, probe_post_comparisons, probe_custom_comparisons,
         probe_detail_comparisons);
  printf("{\"fast_path_comparisons\":%" PRIu64 "}\n", probe_fast_comparisons);
  return 0;
}
