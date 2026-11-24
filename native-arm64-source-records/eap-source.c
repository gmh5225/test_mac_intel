#include "eap.h"
__declspec(dllexport) DWORD InspectEapHostPeerInvokeConfigUI(
    HWND hwnd, DWORD flags, EAP_METHOD_TYPE method, DWORD size, const BYTE *in,
    DWORD *out_size, BYTE **out, EAP_ERROR **error) {
    return EapHostPeerInvokeConfigUI(hwnd, flags, method, size, in, out_size, out, error);
}
