static bool prefix3458(uint64_t imm)
{
	// find the first hex letter representing imm
	while (imm >= 0x10)
		imm >>= 4;

	if (imm < 0xa)
		return false;
	else // this need 0 prefix
		return true;
}

static void immediate3458(MCInst *MI, SStream *O, int64_t imm, bool positive)
{
	if (positive) {
		// always print this number in positive form
		if (MI->csh->syntax == CS_OPT_SYNTAX_MASM) {
			if (imm < 0) {
				if (MI->op1_size) {
					switch (MI->op1_size) {
					default:
						break;
					case 1:
						imm &= 0xff;
						break;
					case 2:
						imm &= 0xffff;
						break;
					case 4:
						imm &= 0xffffffff;
						break;
					}
				}

				if (imm == 0x8000000000000000LL) // imm == -imm
					SStream_concat0(O, "8000000000000000h");
				else if (prefix3458(imm))
					X86_printMasmHexToken(O, "0%" PRIx64 "h", imm);
				else
					X86_printMasmHexToken(O, "%" PRIx64 "h", imm);
			} else {
				if (imm > HEX_THRESHOLD) {
					if (prefix3458(imm))
						X86_printMasmHexToken(O,
							       "0%" PRIx64 "h",
							       imm);
					else
						X86_printMasmHexToken(
							O, "%" PRIx64 "h", imm);
				} else
					SStream_concat_dec64(O, imm, false);
			}
		} else { // Intel syntax
			if (imm < 0) {
				if (MI->op1_size) {
					switch (MI->op1_size) {
					default:
						break;
					case 1:
						imm &= 0xff;
						break;
					case 2:
						imm &= 0xffff;
						break;
					case 4:
						imm &= 0xffffffff;
						break;
					}
				}

				SStream_concat_hex64(O, imm, false);
			} else {
				if (imm > HEX_THRESHOLD)
					SStream_concat_hex64(O, imm, false);
				else
					SStream_concat_dec64(O, imm, false);
			}
		}
	} else {
		if (MI->csh->syntax == CS_OPT_SYNTAX_MASM) {
			if (imm < 0) {
				if (imm == 0x8000000000000000LL) // imm == -imm
					SStream_concat0(O, "8000000000000000h");
				else if (imm < -HEX_THRESHOLD) {
					if (prefix3458(imm))
						X86_printMasmHexToken(O,
							       "-0%" PRIx64 "h",
							       -imm);
					else
						X86_printMasmHexToken(O,
							       "-%" PRIx64 "h",
							       -imm);
				} else
					SStream_concat_dec64(O, (uint64_t)-imm,
							     true);
			} else {
				if (imm > HEX_THRESHOLD) {
					if (prefix3458(imm))
						X86_printMasmHexToken(O,
							       "0%" PRIx64 "h",
							       imm);
					else
						X86_printMasmHexToken(
							O, "%" PRIx64 "h", imm);
				} else
					SStream_concat_dec64(O, imm, false);
			}
		} else { // Intel syntax
			if (imm < 0) {
				if (imm == 0x8000000000000000LL) // imm == -imm
					SStream_concat0(O,
							"0x8000000000000000");
				else if (imm < -HEX_THRESHOLD)
					SStream_concat_hex64(O, (uint64_t)-imm,
							     true);
				else
					SStream_concat_dec64(O, (uint64_t)-imm,
							     true);

			} else {
				if (imm > HEX_THRESHOLD)
					SStream_concat_hex64(O, imm, false);
				else
					SStream_concat_dec64(O, imm, false);
			}
		}
	}
}

