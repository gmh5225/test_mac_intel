#include "eap.h"
__typeof__(EapHostPeerInvokeConfigUI) InspectEapHostPeerInvokeConfigUI;
static DWORD check(EAP_METHOD_TYPE method, ULONG_PTR last) {
    return InspectEapHostPeerInvokeConfigUI((HWND)(ULONG_PTR)0x12340, 0x91a2b3c4, method, 13,
                                           (const BYTE *)(ULONG_PTR)0x12348, (DWORD *)(ULONG_PTR)0x12350,
                                           (BYTE **)(ULONG_PTR)0x12358, (EAP_ERROR **)last);
}
int main(void) {
    EAP_METHOD_TYPE method = {{0xe9,0x8a456721,0xa1b2c3d4},0xfadebc89};
    if (check(method, 0x12360) != 0xf2345678 || check(method, 0x12368) != 0) return 1;
    method.eapType.dwVendorId ^= 1;
    if (check(method, 0x12360) != 0) return 2;
    method.eapType.dwVendorId ^= 1;
    method.dwAuthorId ^= 1;
    return check(method, 0x12360) != 0 ? 3 : 0;
}
