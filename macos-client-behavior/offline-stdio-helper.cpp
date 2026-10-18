// Self-authored hook/MCP/permission fixtures; no target code included.
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <fcntl.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <stdexcept>
using J=nlohmann::json;
namespace fs=std::filesystem;
void require(bool v,const char *s){if(!v)throw std::runtime_error(s);}
std::string boundedInput(bool oneLine){std::string s;char c;while(std::cin.get(c)){if(oneLine&&c=='\n')break;require(s.size()<1024*1024,"input budget");s+=c;}return s;}
void append(const fs::path &path,const J &j){std::ofstream o(path,std::ios::app);o<<j.dump()<<'\n';require(bool(o),"log write");}
void emit(const J &j){std::cout<<j.dump()<<'\n'<<std::flush;}
int main(int argc,char**argv)try{
 require(argc>=2,"mode");std::string mode=argv[1];
 if(mode=="--mcp-fail")return 2;
 if(mode=="--hook"){
  require(argc==5&&std::string(argv[3])=="--log","hook args");
  auto input=J::parse(boundedInput(false));append(argv[4],input);
  std::string behavior=argv[2];
  if(behavior=="invalid-json")std::cout<<"{ invalid\n";
  else if(behavior=="invalid-schema")emit({{"hookSpecificOutput",{{"hookEventName","PreToolUse"},{"permissionDecision",42}}}});
  else if(behavior=="deny")emit({{"hookSpecificOutput",{{"hookEventName","PreToolUse"},{"permissionDecision","deny"},{"permissionDecisionReason","fixture hook denied"}}}});
  else{require(behavior=="observe","hook mode");emit(J::object());}
  return 0;
 }
 if(mode=="--mcp-echo"){
  require(argc==4&&std::string(argv[2])=="--log","mcp args");
  for(unsigned count=0;count<64;count++){
   auto line=boundedInput(true);if(line.empty()&&std::cin.eof())return 0;
   J request=J::parse(line);append(argv[3],request);
   require(request.value("jsonrpc","")=="2.0","jsonrpc");
   if(!request.contains("id"))continue;
   auto method=request.value("method","");J result;
   if(method=="initialize")result={{"protocolVersion",request.at("params").at("protocolVersion")},{"capabilities",{{"tools",J::object()}}},{"serverInfo",{{"name","offline-fixture"},{"version","1.0"}}}};
   else if(method=="tools/list"){
    J schema={{"type","object"},{"required",J::array({"text"})},{"additionalProperties",false}};
    schema["properties"]["text"]["type"]="string";
    J tool={{"name","echo"},{"description","Echo a self-authored fixture token"},{"inputSchema",schema}};
    result={{"tools",J::array({tool})}};
   }
   else if(method=="tools/call"){
    require(request.at("params").at("name")=="echo","tool name");auto text=request.at("params").at("arguments").at("text").get<std::string>();require(text.size()<1024,"echo size");
    result={{"content",J::array({{{"type","text"},{"text","fixture-mcp:"+text}}})},{"isError",false}};
   }else{emit({{"jsonrpc","2.0"},{"id",request.at("id")},{"error",{{"code",-32601},{"message","Method not found"}}}});continue;}
   emit({{"jsonrpc","2.0"},{"id",request.at("id")},{"result",result}});
  }return 0;
 }
 if(mode=="--permission-fixture"){
  J input={{"file_path","/fixture/created.txt"},{"content","fixture-write\n"}};
  emit({{"type","control_request"},{"request_id","self-permission-id"},{"request",{{"subtype","can_use_tool"},{"tool_name","Write"},{"input",input},{"tool_use_id","self-tool-id"}}}});
  auto reply=J::parse(boundedInput(true));require(reply.at("response").at("request_id")=="self-permission-id","permission correlation");
  auto response=reply.at("response").at("response");auto behavior=response.at("behavior").get<std::string>();
  require(behavior=="deny"||(behavior=="allow"&&response.at("updatedInput")==input),"permission value");
  emit({{"type","result"},{"ok",true},{"behavior",behavior}});return 0;
 }
 if(mode=="--probe"){
  require(argc==3,"probe args");J result;
  int file=open(argv[2],O_RDONLY);result["denied_file_errno"]=file<0?errno:0;if(file>=0)close(file);
  int sock=socket(AF_INET,SOCK_STREAM,0);sockaddr_in address{};address.sin_family=AF_INET;address.sin_port=htons(443);inet_pton(AF_INET,"198.51.100.1",&address.sin_addr);int rc=connect(sock,reinterpret_cast<sockaddr*>(&address),sizeof(address));result["external_connect_errno"]=rc?errno:0;close(sock);
  pid_t pid;char exe[]="/usr/bin/true";char* child[]={exe,nullptr};char* env[]={nullptr};int spawned=posix_spawn(&pid,exe,nullptr,nullptr,child,env);result["other_exec_errno"]=spawned;if(!spawned){int status;waitpid(pid,&status,0);}emit(result);return 0;
 }
 if(mode=="--write-parent-fixture"){
  require(argc==3&&!fs::exists(argv[2]),"fixture path");std::ofstream o(argv[2]);
  o<<R"JS(const child=Bun.spawn([process.argv[2],'--probe',process.argv[3]],{stdout:'pipe',stderr:'pipe',env:{PATH:'/usr/bin:/bin'}});
const data=JSON.parse(await new Response(child.stdout).text());
const code=await child.exited;
console.log(JSON.stringify({code,child:data}));
)JS";return o?0:1;
 }
 throw std::runtime_error("unknown helper mode");
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 2;}
