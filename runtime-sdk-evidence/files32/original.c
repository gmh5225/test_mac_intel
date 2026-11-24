#define WINAPI __stdcall

__declspec(dllimport) void *WINAPI
CreateFileW(const unsigned short *Name, unsigned long Access,
            unsigned long Share, void *Security, unsigned long Disposition,
            unsigned long Flags, void *Template);
__declspec(dllimport) int WINAPI CloseHandle(void *Handle);
__declspec(dllimport) unsigned long WINAPI GetLastError(void);
__declspec(dllimport) __declspec(noreturn) void WINAPI
ExitProcess(unsigned Code);
__declspec(dllimport) int WINAPI MessageBoxW(void *Window,
                                             const unsigned short *Text,
                                             const unsigned short *Caption,
                                             unsigned Type);
__declspec(dllimport) long WINAPI ZwClose(void *Handle);
__declspec(dllimport) int WINAPI SetFilePointerEx(void *File,
                                                  long long Distance,
                                                  long long *Position,
                                                  unsigned long Method);

__declspec(dllexport) int Seek(void *Handle, long long Offset) {
  // Position lies on the stack above the five slots the call passes.
  long long Position = 0;
  if (!SetFilePointerEx(Handle, Offset, &Position, 0))
    return -1;
  return (int)Position;
}
