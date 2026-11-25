#include <windows.h>
__declspec(dllimport) BOOL WINAPI ProcessPrng(PBYTE, SIZE_T);
__typeof__(&ProcessPrng) neverd_ucrt_abi_0=&ProcessPrng;
__declspec(dllexport) BOOL __cdecl InspectProcessPrng(PBYTE p, SIZE_T n) { return ProcessPrng(p,n); }
