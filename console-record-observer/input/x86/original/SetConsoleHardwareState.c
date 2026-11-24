#include "observer.h"
__declspec(dllexport) BOOL __cdecl InspectSetConsoleHardwareState(HANDLE hConsoleOutput, COORD dwResolution, COORD dwFontSize) { return SetConsoleHardwareState(hConsoleOutput,dwResolution,dwFontSize); }
