#include "Enclave_u.h"
#include "sgx_urts.h"
#include <cinttypes>
#include <cstdio>

int main() {
    sgx_enclave_id_t enclave = 0;
    sgx_status_t status = sgx_create_enclave("enclave.signed.so", SGX_DEBUG_FLAG,
                                             nullptr, nullptr, &enclave, nullptr);
    if (status != SGX_SUCCESS) {
        std::fprintf(stderr, "sgx_create_enclave returned 0x%x\n", status);
        return 1;
    }
    const uint32_t divisors[] = {7, 0, 0};
    for (const uint32_t divisor : divisors) {
        uint64_t receipt[8] = {};
        int result = -1;
        status = check_divide(enclave, &result, divisor, receipt);
        std::printf("divisor=%u status=%u result=%d handler=%" PRIu64
                    " vector=%" PRIu64 " type=%" PRIu64 " original_pc=%" PRIu64
                    " rax=%" PRIu64 " rdx=%" PRIu64 " r9=%016" PRIx64
                    " quotient=%" PRIu64 "\n", divisor, status, result,
                    receipt[0], receipt[1], receipt[2], receipt[3],
                    receipt[4], receipt[5], receipt[6], receipt[7]);
        if (status != SGX_SUCCESS || result != 0 || receipt[7] != 12 ||
            receipt[0] != (divisor == 0) ||
            (!divisor && (receipt[1] != 0 || receipt[2] != 3 ||
                          receipt[3] != 1 || receipt[4] != 84 ||
                          receipt[5] != 0 || receipt[6] != 0x1122334455667788ULL)))
            return 2;
    }
    uint32_t instruction_status[5] = {}, intact = 0, data_match = 0;
    int result = -1;
    status = check_key_errors(enclave, &result, instruction_status, &intact);
    std::printf("key_errors=%u,%u,%u,%u,%u intact_outputs=%u result=%d status=%u\n",
                instruction_status[0], instruction_status[1], instruction_status[2],
                instruction_status[3], instruction_status[4], intact, result, status);
    if (status != SGX_SUCCESS || result || intact != 5 ||
        instruction_status[0] != 2 || instruction_status[1] != 2 ||
        instruction_status[2] != 2 || instruction_status[3] != 256 ||
        instruction_status[4] != 256)
        return 4;
    status = check_local_report(enclave, &result, &data_match);
    std::printf("self_report_verified=%u reportdata_match=%u result=%d status=%u\n",
                status == SGX_SUCCESS && result == 0, data_match, result, status);
    if (status != SGX_SUCCESS || result || !data_match)
        return 5;
    return sgx_destroy_enclave(enclave) == SGX_SUCCESS ? 0 : 3;
}
