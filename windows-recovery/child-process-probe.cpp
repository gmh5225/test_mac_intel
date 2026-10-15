// Authored boundary probe: raw Win32 process/pipe APIs versus Bun's spawn.
#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <string>
DWORD execute(const std::wstring &exe,const std::wstring &arg,DWORD &error) {
  std::wstring command=L"\""+exe+L"\" "+arg;
  STARTUPINFOW startup{};startup.cb=sizeof(startup);PROCESS_INFORMATION process{};
  if(!CreateProcessW(exe.c_str(),command.data(),nullptr,nullptr,FALSE,CREATE_NO_WINDOW,
                     nullptr,nullptr,&startup,&process)){error=GetLastError();return DWORD(-1);}
  error=0;DWORD code=0;
  if(WaitForSingleObject(process.hProcess,5000)==WAIT_TIMEOUT)TerminateProcess(process.hProcess,124);
  WaitForSingleObject(process.hProcess,5000);GetExitCodeProcess(process.hProcess,&code);
  CloseHandle(process.hThread);CloseHandle(process.hProcess);return code;
}
int wmain(int argc,wchar_t **argv) {
  if(argc==2&&std::wstring(argv[1])==L"--child"){
    HANDLE token=nullptr;DWORD value=0,returned=0;
    if(!OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&token))return 44;
    const bool ok=GetTokenInformation(token,TokenIsAppContainer,&value,sizeof(value),&returned);
    CloseHandle(token);return ok&&value==1?42:43;
  }
  if(argc!=2)return 2;
  wchar_t self[32768];const auto length=GetModuleFileNameW(nullptr,self,32768);if(!length||length==32768)return 3;
  DWORD nativeError=0,bunError=0;
  const auto nativeCode=execute(self,L"--child",nativeError);
  const auto bunCode=execute(argv[1],L"--mcp-fail",bunError);
  std::cout<<"{\"native_child_error\":"<<nativeError<<",\"native_child_exit\":"<<nativeCode
           <<",\"bun_child_error\":"<<bunError<<",\"bun_child_exit\":"<<bunCode;
  for(const auto &kind:{std::wstring(L"ordinary"),std::wstring(L"local")}) {
    const auto name=L"\\\\.\\pipe\\"+(kind==L"local"?std::wstring(L"LOCAL\\"):std::wstring())+
                    L"neverd-authored-"+std::to_wstring(GetCurrentProcessId());
    HANDLE pipe=CreateNamedPipeW(name.c_str(),PIPE_ACCESS_DUPLEX|FILE_FLAG_OVERLAPPED,PIPE_TYPE_BYTE,1,4096,4096,0,nullptr);
    const auto error=pipe==INVALID_HANDLE_VALUE?GetLastError():0;if(pipe!=INVALID_HANDLE_VALUE)CloseHandle(pipe);
    std::cout<<(kind==L"local"?",\"local_pipe_error\":":",\"ordinary_pipe_error\":")<<error;
  }
  HANDLE read=nullptr,write=nullptr;SECURITY_ATTRIBUTES attributes{sizeof(attributes),nullptr,TRUE};
  const auto created=CreatePipe(&read,&write,&attributes,4096);const auto pipeError=created?0:GetLastError();
  if(created){CloseHandle(read);CloseHandle(write);}
  HANDLE nullFile=CreateFileW(L"NUL",GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,
                             nullptr,OPEN_EXISTING,0,nullptr);
  const auto nullError=nullFile==INVALID_HANDLE_VALUE?GetLastError():0;if(nullFile!=INVALID_HANDLE_VALUE)CloseHandle(nullFile);
  std::cout<<",\"anonymous_pipe_error\":"<<pipeError<<",\"null_file_error\":"<<nullError<<"}\n";
  return 0;
}
