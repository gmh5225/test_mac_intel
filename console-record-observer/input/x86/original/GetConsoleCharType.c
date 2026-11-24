#include "observer.h"
__declspec(dllexport) BOOL __cdecl InspectGetConsoleCharType(HANDLE hConsole, COORD coordCheck, PDWORD pdwType) { return GetConsoleCharType(hConsole,coordCheck,pdwType); }
