#include "observer.h"
__declspec(dllimport) BOOL __cdecl InspectGetConsoleCharType(HANDLE, COORD, PDWORD);
__declspec(dllimport) BOOL __cdecl InspectRegisterConsoleVDM(DWORD, HANDLE, HANDLE, HANDLE, DWORD, LPDWORD, PVOID *, COORD, PVOID *);
__declspec(dllimport) BOOL __cdecl InspectSetConsoleHardwareState(HANDLE, COORD, COORD);
__declspec(dllimport) BOOL __cdecl InspectSetConsoleLocalEUDC(HANDLE, WORD, COORD, PCHAR);
__declspec(dllimport) __declspec(noreturn) void __stdcall ExitProcess(unsigned);
static unsigned run(void) {
    COORD a={-32767,0x527b}, b={0x41a7,-7123};
    for (unsigned i=0; i<32; ++i) {
        DWORD small[2]={0xa7b38062,0x80603175}, n=0xa5c63120;
        PVOID state=&n, buf=&state;
        char text[2]={0x61,0x3d};
        if (InspectGetConsoleCharType(small,a,small+1)!=-7 ||
            small[0]!=0xa7b38062 || small[1]!=0xd7fb438c) return 1;
        if (InspectRegisterConsoleVDM(0xedcba019,&n,&state,&buf,0x81253374,&n,&state,b,&buf)!=-11 ||
            n!=0xf7ab899d || state!=&state || buf!=&n) return 2;
        if (InspectSetConsoleHardwareState(&n,a,b)!=-17) return 3;
        if (InspectSetConsoleLocalEUDC(text+1,0xf129,a,text)!=-23 ||
            text[0]!=0x72 || text[1]!=0x3d) return 4;
    }
    return 0;
}
void __cdecl mainCRTStartup(void) { ExitProcess(run()); }
