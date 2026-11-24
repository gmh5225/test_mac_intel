#include "observer.h"
__declspec(dllexport) BOOL __cdecl InspectSetConsoleLocalEUDC(HANDLE hConsoleHandle, WORD wCodePoint, COORD cFontSize, PCHAR lpSB) { return SetConsoleLocalEUDC(hConsoleHandle,wCodePoint,cFontSize,lpSB); }
