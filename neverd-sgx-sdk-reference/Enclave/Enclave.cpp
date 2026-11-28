#include "Enclave_t.h"
#include "sgx_trts_exception.h"
#include "sgx_utils.h"
#include <string.h>

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

// The tRTS entry returns the instruction status. The public sgx_get_key
// wrapper intentionally randomizes the caller's buffer on errors.
extern "C" int do_egetkey(const sgx_key_request_t *, sgx_key_128bit_t *);

int check_key_errors(uint32_t *status, uint32_t *intact) {
    const uint16_t names[] = {SGX_KEYSELECT_EINITTOKEN, SGX_KEYSELECT_PROVISION,
                              SGX_KEYSELECT_PROVISION_SEAL, 5, 0xffff};
    *intact = 0;
    for (unsigned i = 0; i < 5; ++i) {
        alignas(512) sgx_key_request_t request = {};
        alignas(16) sgx_key_128bit_t output;
        request.key_name = names[i];
        memset(output, 0xa5, sizeof(output));
        status[i] = do_egetkey(&request, &output);
        for (const auto byte : output)
            if (byte != 0xa5)
                return 1;
        ++*intact;
    }
    return 0;
}

int check_local_report(uint32_t *data_match) {
    sgx_target_info_t target = {};
    sgx_report_data_t data = {};
    sgx_report_t report = {};
    for (unsigned i = 0; i < sizeof(data.d); ++i)
        data.d[i] = static_cast<uint8_t>(3 * i + 1);
    if (sgx_self_target(&target) != SGX_SUCCESS ||
        sgx_create_report(&target, &data, &report) != SGX_SUCCESS)
        return 1;
    *data_match = memcmp(report.body.report_data.d, data.d, sizeof(data.d)) == 0;
    return sgx_verify_report(&report) == SGX_SUCCESS ? 0 : 2;
}
