// Authored Windows test launcher. Every run creates a new capability-free profile.
#define NOMINMAX
#include <windows.h>
#include <userenv.h>
#include <aclapi.h>
#include <sddl.h>
#include <filesystem>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>
#include <algorithm>
#include <netfw.h>
namespace fs = std::filesystem;
void need(bool ok, const char *what) {
  if (!ok) throw std::runtime_error(std::string(what) + ": " + std::to_string(GetLastError()));
}
void checkCode(DWORD code, const char *what) { SetLastError(code); need(code==ERROR_SUCCESS,what); }
struct Handle {
  HANDLE h = nullptr;
  ~Handle() { if (h && h != INVALID_HANDLE_VALUE) CloseHandle(h); }
};
std::wstring quoted(const std::wstring &s) {
  std::wstring out=L"\""; unsigned slashes=0;
  for(wchar_t c:s) {
    if(c==L'\\') { ++slashes; continue; }
    if(c==L'"') { out.append(slashes*2+1,L'\\');out+=c;slashes=0;continue; }
    out.append(slashes,L'\\');slashes=0;out+=c;
  }
  out.append(slashes*2,L'\\');return out+L'"';
}
void grant(const fs::path &path, PSID sid, DWORD mask, DWORD inheritance) {
  PACL oldAcl=nullptr,newAcl=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
  auto name=path.wstring();
  auto result=GetNamedSecurityInfoW(name.data(),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,
                                  nullptr,nullptr,&oldAcl,nullptr,&descriptor);
  checkCode(result,"read task ACL");
  EXPLICIT_ACCESSW access{};access.grfAccessPermissions=mask;access.grfAccessMode=GRANT_ACCESS;
  access.grfInheritance=inheritance;access.Trustee.TrusteeForm=TRUSTEE_IS_SID;
  access.Trustee.TrusteeType=TRUSTEE_IS_UNKNOWN;access.Trustee.ptstrName=static_cast<LPWSTR>(sid);
  result=SetEntriesInAclW(1,&access,oldAcl,&newAcl);
  if(result==ERROR_SUCCESS)result=SetNamedSecurityInfoW(name.data(),SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION,nullptr,nullptr,newAcl,nullptr);
  if(newAcl)LocalFree(newAcl);if(descriptor)LocalFree(descriptor);
  checkCode(result,"grant task ACL");
}
struct Profile {
  std::wstring name;PSID sid=nullptr;
  ~Profile(){if(sid){FreeSid(sid);DeleteAppContainerProfile(name.c_str());}}
};
// libuv opens NUL inside the child when a stdio stream is ignored. This device
// needs a handle ACL; filesystem grants and inherited handles do not cover it.
struct NullDevicePermission {
  PSID sid;Handle device;bool active=false;
  explicit NullDevicePermission(PSID value):sid(value),device{CreateFileW(L"\\\\.\\NUL",
      READ_CONTROL|WRITE_DAC,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,0,nullptr)} {
    need(device.h!=INVALID_HANDLE_VALUE,"open NUL ACL");change(true);active=true;
  }
  void change(bool allow) {
    PACL prior=nullptr,updated=nullptr;PSECURITY_DESCRIPTOR descriptor=nullptr;
    auto result=GetSecurityInfo(device.h,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,
                                nullptr,nullptr,&prior,nullptr,&descriptor);
    checkCode(result,"read NUL ACL");
    EXPLICIT_ACCESSW access{};access.grfAccessPermissions=allow?GENERIC_READ|GENERIC_WRITE:0;
    access.grfAccessMode=allow?GRANT_ACCESS:REVOKE_ACCESS;access.grfInheritance=NO_INHERITANCE;
    access.Trustee.TrusteeForm=TRUSTEE_IS_SID;access.Trustee.TrusteeType=TRUSTEE_IS_WELL_KNOWN_GROUP;
    access.Trustee.ptstrName=static_cast<LPWSTR>(sid);
    result=SetEntriesInAclW(1,&access,prior,&updated);
    if(result==ERROR_SUCCESS)result=SetSecurityInfo(device.h,SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,
        nullptr,nullptr,updated,nullptr);
    if(updated)LocalFree(updated);if(descriptor)LocalFree(descriptor);
    checkCode(result,allow?"grant task NUL access":"remove task NUL access");
  }
  void close(){if(active){change(false);active=false;}}
  ~NullDevicePermission(){if(active)try{close();}catch(const std::exception&e){std::cerr<<e.what()<<'\n';}}
};
// Preserve other profiles and remove only this run's temporary exemption.
struct LoopbackPermission {
  PSID sid; bool active=false;
  void change(bool allow) {
    const auto library=LoadLibraryExW(L"FirewallAPI.dll",nullptr,LOAD_LIBRARY_SEARCH_SYSTEM32);
    need(library!=nullptr,"system FirewallAPI");
    using Get=DWORD(WINAPI *)(DWORD *,PSID_AND_ATTRIBUTES *);
    using Set=DWORD(WINAPI *)(DWORD,PSID_AND_ATTRIBUTES);
    const auto get=reinterpret_cast<Get>(GetProcAddress(library,"NetworkIsolationGetAppContainerConfig"));
    const auto setConfig=reinterpret_cast<Set>(GetProcAddress(library,"NetworkIsolationSetAppContainerConfig"));
    if(!get||!setConfig){FreeLibrary(library);throw std::runtime_error("loopback isolation API unavailable");}
    DWORD count=0;PSID_AND_ATTRIBUTES prior=nullptr;auto result=get(&count,&prior);
    if(result!=ERROR_SUCCESS){FreeLibrary(library);checkCode(result,"read loopback exemptions");}
    std::vector<SID_AND_ATTRIBUTES> updated;
    for(DWORD i=0;i<count;i++)if(!EqualSid(prior[i].Sid,sid))updated.push_back(prior[i]);
    if(allow)updated.push_back({sid,0});
    result=setConfig(static_cast<DWORD>(updated.size()),updated.empty()?nullptr:updated.data());
    for(DWORD i=0;i<count;i++)HeapFree(GetProcessHeap(),0,prior[i].Sid);
    HeapFree(GetProcessHeap(),0,prior);FreeLibrary(library);
    checkCode(result,allow?"enable task loopback":"remove task loopback");
  }
  void enable(){change(true);active=true;}
  void close(){if(active){change(false);active=false;}}
  ~LoopbackPermission(){if(active)try{close();}catch(const std::exception&e){std::cerr<<e.what()<<'\n';}}
};
void writableLabel(const fs::path &path) {
  PSECURITY_DESCRIPTOR descriptor=nullptr;
  need(ConvertStringSecurityDescriptorToSecurityDescriptorW(L"S:(ML;OICI;NW;;;LW)",
      SDDL_REVISION_1,&descriptor,nullptr),"low integrity descriptor");
  PACL sacl=nullptr;BOOL present=FALSE,defaulted=FALSE;
  need(GetSecurityDescriptorSacl(descriptor,&present,&sacl,&defaulted)&&present,"low integrity ACL");
  auto name=path.wstring();auto result=SetNamedSecurityInfoW(name.data(),SE_FILE_OBJECT,
      LABEL_SECURITY_INFORMATION,nullptr,nullptr,nullptr,sacl);
  LocalFree(descriptor);checkCode(result,"task writable integrity label");
}
int wmain(int argc,wchar_t **argv) try {
  need(argc>=5,"stage profile deadline-ms executable [args]");
  const auto root=fs::canonical(argv[1]);
  const auto deadline=std::stoul(argv[3]);need(deadline>0&&deadline<=60000,"deadline");
  bool interactive=false,loopback=false;int exeIndex=4;
  while(exeIndex<argc) {
    const std::wstring option=argv[exeIndex];
    if(option==L"--interactive"){need(!interactive,"duplicate stdin option");interactive=true;}
    else if(option==L"--loopback"){need(!loopback,"duplicate loopback option");loopback=true;}
    else break;
    ++exeIndex;
  }
  need(argc>exeIndex,"executable argument");
  const std::wstring filename=argv[exeIndex];
  need(filename.find_first_of(L"/\\:")==std::wstring::npos,"executable basename");
  const auto executable=root/L"bin"/filename;
  need(fs::is_regular_file(executable),"executable file");
  Profile profile{argv[2]};
  need(profile.name.size()>=16&&profile.name.size()<=64&&
       std::all_of(profile.name.begin(),profile.name.end(),[](wchar_t c){
         return (c>=L'a'&&c<=L'z')||(c>=L'A'&&c<=L'Z')||(c>=L'0'&&c<=L'9')||c==L'.';}),"profile name");
  std::transform(profile.name.begin(),profile.name.end(),profile.name.begin(),
                 [](wchar_t c){return c>=L'A'&&c<=L'Z'?c-L'A'+L'a':c;});
  const auto profileResult=CreateAppContainerProfile(profile.name.c_str(),L"NeverD fixture",
      L"Disposable capability-free recovery test",nullptr,0,&profile.sid);
  if(FAILED(profileResult))throw std::runtime_error("create AppContainer HRESULT: "+std::to_string(profileResult));
  NullDevicePermission nullDevice{profile.sid};
  LoopbackPermission network{profile.sid};if(loopback)network.enable();
  // Windows redirects TEMP beneath the explicit LOCALAPPDATA supplied by the
  // caller. Prepare that disposable path before applying inherited task ACLs.
  const auto redirectedTemp=root/L"home"/L"Packages"/profile.name/L"AC"/L"Temp";
  fs::create_directories(redirectedTemp);
  grant(root,profile.sid,FILE_TRAVERSE|FILE_READ_ATTRIBUTES|SYNCHRONIZE,NO_INHERITANCE);
  grant(root/L"bin",profile.sid,FILE_GENERIC_READ|FILE_GENERIC_EXECUTE,SUB_CONTAINERS_AND_OBJECTS_INHERIT);
  for(const auto *name:{L"work",L"home",L"tmp"}) {
    grant(root/name,profile.sid,FILE_ALL_ACCESS,SUB_CONTAINERS_AND_OBJECTS_INHERIT);
    writableLabel(root/name);
  }
  writableLabel(redirectedTemp);
  if(fs::is_directory(root/L"sibling"))
    grant(root/L"sibling",profile.sid,FILE_GENERIC_READ|FILE_GENERIC_EXECUTE,SUB_CONTAINERS_AND_OBJECTS_INHERIT);
  if(fs::is_directory(root/L"helper-log")) {
    grant(root/L"helper-log",profile.sid,FILE_ALL_ACCESS,SUB_CONTAINERS_AND_OBJECTS_INHERIT);
    writableLabel(root/L"helper-log");
  }
  SECURITY_ATTRIBUTES inherit{sizeof(SECURITY_ATTRIBUTES),nullptr,TRUE};
  Handle input;
  if(interactive) {
    need(DuplicateHandle(GetCurrentProcess(),GetStdHandle(STD_INPUT_HANDLE),GetCurrentProcess(),
                         &input.h,0,TRUE,DUPLICATE_SAME_ACCESS),"interactive stdin handle");
  } else input.h=CreateFileW(L"NUL",GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,&inherit,OPEN_EXISTING,0,nullptr);
  Handle output{CreateFileW((root/L"target.stdout").c_str(),GENERIC_WRITE|GENERIC_READ,FILE_SHARE_READ,
      &inherit,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr)};
  Handle error{CreateFileW((root/L"target.stderr").c_str(),GENERIC_WRITE|GENERIC_READ,FILE_SHARE_READ,
      &inherit,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,nullptr)};
  need(input.h!=INVALID_HANDLE_VALUE&&output.h!=INVALID_HANDLE_VALUE&&error.h!=INVALID_HANDLE_VALUE,"stdio files");
  Handle job{CreateJobObjectW(nullptr,nullptr)};need(job.h!=nullptr,"job object");
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE|JOB_OBJECT_LIMIT_ACTIVE_PROCESS|
      JOB_OBJECT_LIMIT_JOB_MEMORY|JOB_OBJECT_LIMIT_JOB_TIME;
  limits.BasicLimitInformation.ActiveProcessLimit=24;
  limits.BasicLimitInformation.PerJobUserTimeLimit.QuadPart=60LL*10000000;
  limits.JobMemoryLimit=2ULL*1024*1024*1024;
  need(SetInformationJobObject(job.h,JobObjectExtendedLimitInformation,&limits,sizeof(limits)),"job limits");
  SIZE_T bytes=0;InitializeProcThreadAttributeList(nullptr,2,0,&bytes);
  std::vector<unsigned char> storage(bytes);
  auto attributes=reinterpret_cast<PPROC_THREAD_ATTRIBUTE_LIST>(storage.data());
  need(InitializeProcThreadAttributeList(attributes,2,0,&bytes),"process attributes");
  SECURITY_CAPABILITIES capabilities{};capabilities.AppContainerSid=profile.sid;
  HANDLE handles[]={input.h,output.h,error.h};
  need(UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
      &capabilities,sizeof(capabilities),nullptr,nullptr),"security capabilities");
  need(UpdateProcThreadAttribute(attributes,0,PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
      handles,sizeof(handles),nullptr,nullptr),"explicit inherited handles");
  STARTUPINFOEXW startup{};startup.StartupInfo.cb=sizeof(startup);
  startup.StartupInfo.dwFlags=STARTF_USESTDHANDLES;startup.StartupInfo.hStdInput=input.h;
  startup.StartupInfo.hStdOutput=output.h;startup.StartupInfo.hStdError=error.h;startup.lpAttributeList=attributes;
  std::wstring command=quoted(executable.wstring());for(int i=exeIndex+1;i<argc;i++)command+=L" "+quoted(argv[i]);
  PROCESS_INFORMATION process{};
  const auto created=CreateProcessW(executable.c_str(),command.data(),nullptr,nullptr,TRUE,
      EXTENDED_STARTUPINFO_PRESENT|CREATE_SUSPENDED|CREATE_UNICODE_ENVIRONMENT,nullptr,
      (root/L"work").c_str(),&startup.StartupInfo,&process);
  const auto createError=GetLastError();DeleteProcThreadAttributeList(attributes);
  SetLastError(createError);need(created,"create contained process");
  Handle child{process.hProcess},thread{process.hThread};
  if(!AssignProcessToJobObject(job.h,child.h)){TerminateProcess(child.h,125);need(false,"assign contained process");}
  Handle token;need(OpenProcessToken(child.h,TOKEN_QUERY,&token.h),"inspect child token");
  DWORD appContainer=0,returned=0;
  need(GetTokenInformation(token.h,TokenIsAppContainer,&appContainer,sizeof(appContainer),&returned)&&appContainer==1,
       "child is AppContainer");
  GetTokenInformation(token.h,TokenCapabilities,nullptr,0,&returned);
  std::vector<unsigned char> capabilityBuffer(returned);
  need(GetTokenInformation(token.h,TokenCapabilities,capabilityBuffer.data(),returned,&returned)&&
       reinterpret_cast<TOKEN_GROUPS *>(capabilityBuffer.data())->GroupCount==0,"empty child capabilities");
  need(ResumeThread(thread.h)!=DWORD(-1),"resume contained process");
  const auto started=GetTickCount64();bool timeout=false,outputLimit=false;
  while(WaitForSingleObject(child.h,50)==WAIT_TIMEOUT) {
    LARGE_INTEGER a{},b{};need(GetFileSizeEx(output.h,&a)&&GetFileSizeEx(error.h,&b),"output sizes");
    timeout=GetTickCount64()-started>=deadline;outputLimit=a.QuadPart+b.QuadPart>2*1024*1024;
    if(timeout||outputLimit){TerminateJobObject(job.h,124);WaitForSingleObject(child.h,5000);break;}
  }
  DWORD code=0;need(GetExitCodeProcess(child.h,&code),"child exit code");
  LARGE_INTEGER finalOut{},finalErr{};
  need(GetFileSizeEx(output.h,&finalOut)&&GetFileSizeEx(error.h,&finalErr),"final output sizes");
  outputLimit=outputLimit||finalOut.QuadPart+finalErr.QuadPart>2*1024*1024;
  need(TerminateJobObject(job.h,0),"collect remaining descendants");
  JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting{};
  const auto cleanupStarted=GetTickCount64();
  do {
    need(QueryInformationJobObject(job.h,JobObjectBasicAccountingInformation,&accounting,sizeof(accounting),nullptr),
         "remaining descendants");
    if(accounting.ActiveProcesses==0)break;
    Sleep(25);
  } while(GetTickCount64()-cleanupStarted<5000);
  need(accounting.ActiveProcesses==0,"all contained processes exited");
  network.close();
  nullDevice.close();
  std::cout<<"{\"app_container\":true,\"capability_count\":0,\"exit_code\":"<<code
           <<",\"timeout\":"<<(timeout?"true":"false")<<",\"output_limit\":"<<(outputLimit?"true":"false")
           <<",\"remaining_processes\":0,\"loopback_exemption\":"<<(loopback?"true":"false")
           <<",\"loopback_exemption_removed\":true,\"null_device_grant_removed\":true}\n";
  return timeout||outputLimit?124:0;
} catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 125;}
