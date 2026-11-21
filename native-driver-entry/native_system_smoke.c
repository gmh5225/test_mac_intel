#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#include <snmp.h>
#include <stdio.h>

#define ROUTE(prefix)                                                          \
    BOOL prefix##UseIcmpHandle(HANDLE handle);                                 \
    void prefix##UseSnmpRelease(void *allocation);                             \
    HRESULT prefix##UsePlatformAuthenticator(BOOL *available)

ROUTE();
ROUTE(highc_);
ROUTE(llvmc_);

struct Route {
    const char *name;
    BOOL (*close_handle)(HANDLE);
    void (*release)(void *);
    HRESULT (*available)(BOOL *);
};

int main(void) {
    static const struct Route routes[] = {
        {"original", UseIcmpHandle, UseSnmpRelease, UsePlatformAuthenticator},
        {"highc", highc_UseIcmpHandle, highc_UseSnmpRelease, highc_UsePlatformAuthenticator},
        {"llvmc", llvmc_UseIcmpHandle, llvmc_UseSnmpRelease, llvmc_UsePlatformAuthenticator}
    };
    printf("[");
    for (size_t i = 0; i < sizeof(routes) / sizeof(routes[0]); ++i) {
        HANDLE handle = IcmpCreateFile();
        if (handle == INVALID_HANDLE_VALUE || !routes[i].close_handle(handle))
            return 1;
        BYTE *allocation = SnmpUtilMemAlloc(32);
        if (!allocation)
            return 2;
        allocation[0] = 0x5a;
        routes[i].release(allocation);
        BOOL available = -1;
        HRESULT status = routes[i].available(&available);
        if (SUCCEEDED(status) && available != FALSE && available != TRUE)
            return 3;
        printf("%s{\"route\":\"%s\",\"icmp_closed\":true,\"snmp_release_returned\":true,"
               "\"webauthn_status\":%ld,\"available\":%ld}", i ? "," : "",
               routes[i].name, (long)status, (long)available);
    }
    puts("]");
    return 0;
}
