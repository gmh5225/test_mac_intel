// Self-authored Node-API proof; does not require external headers or import libs.
#define NOMINMAX
#include <windows.h>
#include <cstddef>
using Env=void *;using Value=void *;using Info=void *;
using Callback=Value(*)(Env,Info);
using CreateString=int(*)(Env,const char *,size_t,Value *);
using CreateFunction=int(*)(Env,const char *,size_t,Callback,void *,Value *);
using SetProperty=int(*)(Env,Value,const char *,Value);
CreateString createString=nullptr;
Value proof(Env env,Info) {
  Value result=nullptr;
  if(createString(env,"authored-node-api-ok",size_t(-1),&result))return nullptr;
  return result;
}
extern "C" __declspec(dllexport) Value napi_register_module_v1(Env env,Value exports) {
  const auto host=GetModuleHandleW(nullptr);
  createString=reinterpret_cast<CreateString>(GetProcAddress(host,"napi_create_string_utf8"));
  const auto createFunction=reinterpret_cast<CreateFunction>(GetProcAddress(host,"napi_create_function"));
  const auto setProperty=reinterpret_cast<SetProperty>(GetProcAddress(host,"napi_set_named_property"));
  if(!createString||!createFunction||!setProperty)return nullptr;
  Value function=nullptr;
  if(createFunction(env,"proof",size_t(-1),proof,nullptr,&function)||setProperty(env,exports,"proof",function))return nullptr;
  return exports;
}
extern "C" __declspec(dllexport) int node_api_module_get_api_version_v1(){return 8;}
