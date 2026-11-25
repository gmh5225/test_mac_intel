extern uint64_t profile_names[16];
static bool observedKind(const MCOperand *op, bool reg, bool displacement)
{
	const int tag = reg ? kRegister : kImmediate;
	const bool actual = reg ? MCOperand_isReg(op) : MCOperand_isImm(op);
	++profile_names[1];
	++profile_names[reg ? 2 : 3];
	profile_names[4] += op->Kind == kRegister;
	profile_names[5] += op->Kind == kImmediate;
	profile_names[6] += op->Kind != op->MachineOperandType;
	profile_names[7] += op->Kind != kRegister && op->Kind != kImmediate;
	profile_names[8] += op->Kind != tag;
	profile_names[9] += (op->Kind == tag) != actual;
	profile_names[10] += displacement;
	profile_names[11] += displacement && !actual;
	profile_names[reg ? 12 : 13] += op->Kind != tag;
	return actual;
}
