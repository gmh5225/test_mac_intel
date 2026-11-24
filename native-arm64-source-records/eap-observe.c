#include "eap.h"
DWORD WINAPI ObserveInputs(HWND window, DWORD flags, EAP_METHOD_TYPE method, DWORD size,
                           const BYTE *input, DWORD *out_size, BYTE **output, EAP_ERROR **error) {
    return (ULONG_PTR)window == 0x12340 && flags == 0x91a2b3c4 && method.eapType.type == 0xe9 &&
           method.eapType.dwVendorId == 0x8a456721 && method.eapType.dwVendorType == 0xa1b2c3d4 &&
           method.dwAuthorId == 0xfadebc89 && size == 13 && (ULONG_PTR)input == 0x12348 &&
           (ULONG_PTR)out_size == 0x12350 && (ULONG_PTR)output == 0x12358 &&
           (ULONG_PTR)error == 0x12360 ? 0xf2345678u : 0;
}
__typeof__(&EapHostPeerInvokeConfigUI) __imp_EapHostPeerInvokeConfigUI = ObserveInputs;
