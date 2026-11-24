#include <winsock2.h>
#include <windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include "sslprovider.h"
#include <stdio.h>

SECURITY_STATUS __cdecl InspectSslDecryptPacket(
    NCRYPT_PROV_HANDLE, NCRYPT_KEY_HANDLE, PBYTE, DWORD, PBYTE, DWORD, DWORD *,
    ULONGLONG, DWORD);

static BYTE input[5] = {42};
static BYTE output[11];
static DWORD written;
static ULONGLONG received;

/* Record the arguments at the public CPDK call boundary. */
SECURITY_STATUS WINAPI SslDecryptPacket(
    NCRYPT_PROV_HANDLE provider, NCRYPT_KEY_HANDLE key, PBYTE source,
    DWORD source_size, PBYTE destination, DWORD destination_size,
    DWORD *result_size, ULONGLONG sequence, DWORD flags) {
    if (provider != 0x101 || key != 0x202 || source != input ||
        source_size != sizeof input || destination != output ||
        destination_size != sizeof output || result_size != &written ||
        flags != 0x12345678)
        return -1;
    received = sequence;
    *result_size = source_size;
    destination[0] = source[0];
    return 37;
}

int main(void) {
    const ULONGLONG sequences[] = {
        0xfedcba9876543210ULL, 0x8000000000000000ULL, 0x00000001ffffffffULL
    };
    for (unsigned i = 0; i != sizeof sequences / sizeof sequences[0]; ++i) {
        output[0] = 0;
        written = 0;
        SECURITY_STATUS status = InspectSslDecryptPacket(
            0x101, 0x202, input, sizeof input, output, sizeof output,
            &written, sequences[i], 0x12345678);
        if (status != 37 || output[0] != 42 || written != sizeof input ||
            received != sequences[i])
            return 1;
        printf("%016llx\n", (unsigned long long)received);
    }
    return 0;
}
