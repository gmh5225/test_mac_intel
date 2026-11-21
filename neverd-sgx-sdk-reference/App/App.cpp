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
    return sgx_destroy_enclave(enclave) == SGX_SUCCESS ? 0 : 3;
}
