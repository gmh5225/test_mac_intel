#include "Enclave_t.h"
#include "sgx_trts_exception.h"

extern "C" const unsigned char divide_site[];
static uint64_t captured[7];

static int handle_divide(sgx_exception_info_t *info) {
    auto &cpu = info->cpu_context;
    if (info->exception_vector != SGX_EXCEPTION_VECTOR_DE ||
        cpu.rip != reinterpret_cast<uintptr_t>(divide_site) || cpu.rcx != 0)
        return EXCEPTION_CONTINUE_SEARCH;
    ++captured[0];
    captured[1] = info->exception_vector;
    captured[2] = info->exception_type;
    captured[3] = cpu.rip == reinterpret_cast<uintptr_t>(divide_site);
    captured[4] = cpu.rax;
    captured[5] = cpu.rdx;
    captured[6] = cpu.r9;
    cpu.rcx = 7;
    return EXCEPTION_CONTINUE_EXECUTION;
}

int check_divide(uint32_t divisor, uint64_t *receipt) {
    for (auto &value : captured)
        value = 0;
    void *handle = sgx_register_exception_handler(1, handle_divide);
    if (!handle)
        return 1;
    uint32_t dividend = 84, high = 0;
    asm volatile("movabs $0x1122334455667788, %%r9\n\t"
                 ".globl divide_site\n"
                 "divide_site: divl %%ecx"
                 : "+a"(dividend), "+d"(high), "+c"(divisor) : : "r9", "cc");
    if (!sgx_unregister_exception_handler(handle))
        return 2;
    for (unsigned i = 0; i < 7; ++i)
        receipt[i] = captured[i];
    receipt[7] = dividend;
    return 0;
}
