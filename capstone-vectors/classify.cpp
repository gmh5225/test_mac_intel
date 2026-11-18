#include <cstdio>
#include "X86SimpleOutput.h"
#include "X86GenSimpleOutput.inc"

int main()
{
	unsigned admitted = 0;
	for (unsigned wide = 0; wide < 2; ++wide)
		for (unsigned cls = 0; cls < 4; ++cls)
			for (unsigned opcode = 0; opcode < 256; ++opcode) {
				if (x86_simple_plans[wide][cls][opcode] !=
				    X86_PLAN_PUSH_IMMEDIATE)
					continue;
				const bool push = opcode == 0x68 || opcode == 0x6a;
				const bool vex = !wide &&
						 (opcode == 0xc4 || opcode == 0xc5);
				if (cls || (!push && !vex) ||
				    bool(opcode & 0x80) != vex)
					return 1;
				++admitted;
			}
	std::printf("2048 plan cells checked; %u exceptional entries\n", admitted);
	return admitted == 6 ? 0 : 2;
}
