#define BUILD_OBSERVER
#include "observer.h"
static int first(COORD p) { return p.X == -32767 && p.Y == 0x527b; }
static int second(COORD p) { return p.X == 0x41a7 && p.Y == -7123; }
BOOL __stdcall GetConsoleCharType(HANDLE h, COORD p, PDWORD out) {
    if (h != out - 1 || !first(p) || *out != 0x80603175) return 0;
    *out = 0xd7fb438c;
    return -7;
}
BOOL __stdcall RegisterConsoleVDM(DWORD flags, HANDLE a, HANDLE b, HANDLE c, DWORD reserved,
                                  LPDWORD n, PVOID *state, COORD p, PVOID *buf) {
    if (flags != 0xedcba019 || reserved != 0x81253374 || a != n || b != state ||
        c != buf || *n != 0xa5c63120 || *state != n || *buf != state || !second(p)) return 0;
    *n = 0xf7ab899d;
    *state = b;
    *buf = a;
    return -11;
}
BOOL __stdcall SetConsoleHardwareState(HANDLE h, COORD a, COORD b) {
    return h && first(a) && second(b) ? -17 : 0;
}
BOOL __stdcall SetConsoleLocalEUDC(HANDLE h, WORD code, COORD p, PCHAR ch) {
    if (h != ch+1 || code != 0xf129 || !first(p) || *ch != 0x61) return 0;
    *ch = 0x72;
    return -23;
}
