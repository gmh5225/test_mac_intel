#ifndef CONSOLE_OBSERVER_H
#define CONSOLE_OBSERVER_H
typedef int BOOL;
typedef unsigned long DWORD;
typedef DWORD *PDWORD, *LPDWORD;
typedef unsigned short WORD;
typedef void *HANDLE, *PVOID;
typedef char *PCHAR;
typedef struct _COORD { short X, Y; } COORD;
#if defined(BUILD_OBSERVER)
#define OBS __declspec(dllexport)
#else
#define OBS __declspec(dllimport)
#endif
OBS BOOL __stdcall GetConsoleCharType(HANDLE, COORD, PDWORD);
OBS BOOL __stdcall RegisterConsoleVDM(DWORD, HANDLE, HANDLE, HANDLE, DWORD, LPDWORD, PVOID *, COORD, PVOID *);
OBS BOOL __stdcall SetConsoleHardwareState(HANDLE, COORD, COORD);
OBS BOOL __stdcall SetConsoleLocalEUDC(HANDLE, WORD, COORD, PCHAR);
#endif
