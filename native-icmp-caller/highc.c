#include <stdint.h>

extern int32_t IcmpCloseHandle(void *IcmpHandle);

/* neverd.entry: 0x180001000 */
int64_t UseIcmpHandle(void* arg0) {
    return (uint64_t)((uint32_t)IcmpCloseHandle(arg0));
}
__typeof__(&IcmpCloseHandle) neverd_ucrt_abi_0 = &IcmpCloseHandle;
