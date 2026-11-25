#include <capstone/capstone.h>
#include <capstone/riscv.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint64_t now(clockid_t which)
{
	struct timespec t;
	if (clock_gettime(which, &t))
		exit(2);
	return (uint64_t)t.tv_sec * 1000000000 + t.tv_nsec;
}

static csh open_handle(void)
{
	csh h;
	if (cs_open(CS_ARCH_RISCV, CS_MODE_RISCV64, &h) != CS_ERR_OK)
		exit(3);
	return h;
}

int main(int argc, char **argv)
{
	if (argc != 3)
		return 1;
	unsigned mode = (unsigned)strtoul(argv[1], NULL, 10);
	unsigned reps = (unsigned)strtoul(argv[2], NULL, 10);
	if (mode > 2 || !reps)
		return 1;
	csh h = open_handle();
	if (strcmp(cs_reg_name(h, RISCV_REG_X10), "a0") ||
	    cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME) != CS_ERR_OK ||
	    strcmp(cs_reg_name(h, RISCV_REG_X10), "x10") || cs_close(&h) != CS_ERR_OK)
		return 4;
	if (mode == 2)
		h = open_handle();
	uint64_t wall = now(CLOCK_MONOTONIC), cpu = now(CLOCK_PROCESS_CPUTIME_ID);
	for (unsigned i = 0; i < reps; ++i) {
		if (mode != 2)
			h = open_handle();
		if (mode != 0 && cs_option(h, CS_OPT_SYNTAX, CS_OPT_SYNTAX_NOREGNAME) != CS_ERR_OK)
			return 5;
		if (mode != 2 && cs_close(&h) != CS_ERR_OK)
			return 6;
	}
	cpu = now(CLOCK_PROCESS_CPUTIME_ID) - cpu;
	wall = now(CLOCK_MONOTONIC) - wall;
	if (mode == 2 && cs_close(&h) != CS_ERR_OK)
		return 6;
	printf("%llu %llu\n", (unsigned long long)wall, (unsigned long long)cpu);
	return 0;
}
