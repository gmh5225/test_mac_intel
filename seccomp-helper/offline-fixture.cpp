// Self-authored, bounded local protocol fixtures. No external service calls.
#include <nlohmann/json.hpp>
#include <arpa/inet.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <thread>
using J = nlohmann::json;
namespace fs = std::filesystem;
using Clock = std::chrono::steady_clock;
void require(bool b, const char *message) { if (!b) throw std::runtime_error(message); }
J read(const fs::path &p) { std::ifstream in(p); require(bool(in), "input open"); return J::parse(in); }
void log(const fs::path &p, const J &value) { std::ofstream out(p,std::ios::app); out<<value.dump()<<'\n'; require(bool(out),"log write"); }
bool sendAll(int fd, const std::string &s, bool fragment=false) {
  size_t at=0;
  while(at<s.size()) {
    size_t n=fragment?std::min<size_t>(7,s.size()-at):s.size()-at;
    auto sent=send(fd,s.data()+at,n,0); if(sent<=0)return false;at+=sent;
    if(fragment)std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  return true;
}
std::string event(const char *name,J body) { return std::string("event: ")+name+"\ndata: "+body.dump()+"\n\n"; }
std::string message(const J &spec,const J &request,unsigned ordinal) {
  const auto kind=spec.value("kind", "");
  const bool sequence=kind=="tool_sequence_then_text";
  if(sequence) {
    require(spec.contains("tools") && spec["tools"].is_array() && !spec["tools"].empty() && spec["tools"].size()<=8,"tool sequence bound");
    for(const auto &entry:spec["tools"])require(entry.is_object() && entry.contains("name") && entry["name"].is_string() && entry.contains("input") && entry["input"].is_object(),"tool sequence entry");
  }
  const bool tool=(kind=="tool_then_text" && ordinal==1) || (sequence && ordinal>=1 && ordinal<=spec["tools"].size());
  const J selected=tool?(sequence?spec["tools"].at(ordinal-1):spec.at("tool")):J::object();
  std::string model=request.value("model", "claude-sonnet-5");
  std::string result=event("message_start",{{"type","message_start"},{"message",{
    {"id","msg_offline_fixture_"+std::to_string(ordinal)},{"type","message"},{"role","assistant"},
    {"model",model},{"content",J::array()},{"stop_reason",nullptr},{"stop_sequence",nullptr},
    {"usage",{{"input_tokens",10},{"output_tokens",1},{"cache_creation_input_tokens",0},{"cache_read_input_tokens",0}}}}}});
  if(tool) {
    result+=event("content_block_start",{{"type","content_block_start"},{"index",0},
      {"content_block",{{"type","tool_use"},{"id","toolu_offline_fixture_"+std::to_string(ordinal)},{"name",selected.at("name")},{"input",J::object()}}}});
    result+=event("content_block_delta",{{"type","content_block_delta"},{"index",0},
      {"delta",{{"type","input_json_delta"},{"partial_json",selected.at("input").dump()}}}});
  } else {
    result+=event("content_block_start",{{"type","content_block_start"},{"index",0},
      {"content_block",{{"type","text"},{"text",""}}}});
    result+=event("content_block_delta",{{"type","content_block_delta"},{"index",0},
      {"delta",{{"type","text_delta"},{"text",spec.value("text","offline-fixture-complete")}}}});
  }
  if(spec.value("kind","")=="hold_after_text_delta")return result;
  result+=event("content_block_stop",{{"type","content_block_stop"},{"index",0}});
  result+=event("message_delta",{{"type","message_delta"},{"delta",{
    {"stop_reason",tool?"tool_use":"end_turn"},{"stop_sequence",nullptr}}},{"usage",{{"output_tokens",8}}}});
  result+=event("message_stop",{{"type","message_stop"}});
  return result;
}
int serve(const fs::path &specPath,const fs::path &out) {
  J spec=read(specPath);require(fs::is_directory(out),"output directory");
  int server=socket(AF_INET,SOCK_STREAM,0);require(server>=0,"socket");
  sockaddr_in addr{};addr.sin_family=AF_INET;addr.sin_addr.s_addr=htonl(INADDR_LOOPBACK);addr.sin_port=0;
  require(bind(server,reinterpret_cast<sockaddr*>(&addr),sizeof(addr))==0,"bind");
  socklen_t length=sizeof(addr);require(getsockname(server,reinterpret_cast<sockaddr*>(&addr),&length)==0,"getsockname");
  require(listen(server,4)==0,"listen");
  log(out/"ready.jsonl",{{"port",ntohs(addr.sin_port)},{"pid",getpid()}});
  auto deadline=Clock::now()+std::chrono::seconds(55);unsigned requests=0,messages=0;
  while(Clock::now()<deadline&&requests<32) {
    pollfd ready{server,POLLIN,0};if(poll(&ready,1,100)<=0)continue;
    int fd=accept(server,nullptr,nullptr);if(fd<0)continue;
    timeval timeout{5,0};setsockopt(fd,SOL_SOCKET,SO_RCVTIMEO,&timeout,sizeof(timeout));setsockopt(fd,SOL_SOCKET,SO_SNDTIMEO,&timeout,sizeof(timeout));
    std::string data;char chunk[16384];size_t headers=std::string::npos;
    while(data.size()<1024*1024&&(headers=data.find("\r\n\r\n"))==std::string::npos) {auto n=recv(fd,chunk,sizeof(chunk),0);if(n<=0)break;data.append(chunk,n);}
    if(headers==std::string::npos){log(out/"errors.jsonl",{{"error","incomplete header"}});close(fd);continue;}
    std::istringstream lines(data.substr(0,headers));std::string line;std::getline(lines,line);
    auto first=line;std::string path;{std::istringstream requestLine(first);std::string method;requestLine>>method>>path;}
    size_t bodyLength=0;J headerMap=J::object();
    while(std::getline(lines,line)) {if(!line.empty()&&line.back()=='\r')line.pop_back();auto pos=line.find(':');if(pos==std::string::npos)continue;auto key=line.substr(0,pos);for(auto&c:key)c=char(std::tolower(static_cast<unsigned char>(c)));auto value=line.substr(pos+1);headerMap[key]=value;if(key=="content-length")bodyLength=std::stoull(value);}
    require(bodyLength<=1024*1024,"request body budget");require(!headerMap.contains("transfer-encoding"),"chunked request not admitted by fixture");
    while(data.size()<headers+4+bodyLength) {auto n=recv(fd,chunk,sizeof(chunk),0);if(n<=0)break;data.append(chunk,n);}
    require(data.size()>=headers+4+bodyLength,"short request body");
    J body=bodyLength?J::parse(data.substr(headers+4,bodyLength)):J::object();
    log(out/"requests.jsonl",{{"ordinal",++requests},{"request_line",first},{"path",path},{"headers",headerMap},{"body",body}});
    int status=200;std::string type="application/json",payload;
    if(path=="/probe") payload="{\"ok\":true}\n";
    else if(path.starts_with("/v1/messages/count_tokens"))payload="{\"input_tokens\":10}\n";
    else if(path.starts_with("/v1/messages")) {
      ++messages;auto kind=spec.value("kind","");
      if(kind=="http_error") {status=spec.value("status",400);payload=spec.at("body").dump();}
      else if(kind=="forbid_all_requests") {status=500;payload="{\"error\":\"fixture forbids API requests\"}";}
      else {type="text/event-stream";payload=message(spec,body,messages);}
    } else {status=404;payload="{\"error\":\"unplanned fixture endpoint\"}";}
    bool hold=spec.value("kind","")=="hold_after_text_delta"&&type=="text/event-stream";
    std::string header="HTTP/1.1 "+std::to_string(status)+(status==200?" OK\r\n":" Fixture Error\r\n")+
      "Content-Type: "+type+"\r\nConnection: close\r\n"+
      (hold?"":"Content-Length: "+std::to_string(payload.size())+"\r\n")+"\r\n";
    bool sent=sendAll(fd,header)&&sendAll(fd,payload,spec.value("kind","")=="fragmented_text");
    if(hold) {pollfd closed{fd,POLLIN|POLLHUP,0};int n=poll(&closed,1,5000);log(out/"hold.jsonl",{{"poll",n},{"revents",closed.revents}});}
    log(out/"responses.jsonl",{{"request",requests},{"status",status},{"sent",sent},{"body_bytes",payload.size()}});close(fd);
  }
  close(server);return 0;
}
int probe(unsigned allowed,unsigned denied) {
  J rows=J::array();
  for(auto [name,ip,port]:{std::tuple{"allowed","127.0.0.1",allowed},
      std::tuple{"other_port","127.0.0.1",denied},std::tuple{"external","198.51.100.1",allowed}}) {
    int fd=socket(AF_INET,SOCK_STREAM,0);sockaddr_in a{};a.sin_family=AF_INET;a.sin_port=htons(port);inet_pton(AF_INET,ip,&a.sin_addr);
    int ret=connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a));int error=ret?errno:0;
    J row={{"case",name},{"connect_return",ret},{"errno",error}};
    if(ret==0){sendAll(fd,"GET /probe HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");char data[512];auto n=recv(fd,data,sizeof(data),0);row["reply"]=n>0?std::string(data,n):"";}
    rows.push_back(row);close(fd);
  }
  int fd=socket(AF_INET6,SOCK_STREAM,0);sockaddr_in6 a{};a.sin6_family=AF_INET6;a.sin6_port=htons(denied);inet_pton(AF_INET6,"::1",&a.sin6_addr);
  auto rc=connect(fd,reinterpret_cast<sockaddr*>(&a),sizeof(a));rows.push_back({{"case","ipv6_other_port"},{"connect_return",rc},{"errno",rc?errno:0}});close(fd);
  std::cout<<rows.dump()<<'\n';return 0;
}
int main(int argc,char**argv)try {
  signal(SIGPIPE,SIG_IGN);require(argc>=2,"mode");std::string mode=argv[1];
  if(mode=="render") {require(argc==4,"render args");auto spec=read(argv[2]);auto ordinal=std::stoul(argv[3]);require(ordinal>=1 && ordinal<=9,"render ordinal");std::cout<<message(spec,J::object(),ordinal);return 0;}
  if(mode=="serve"){require(argc==4,"serve args");return serve(argv[2],argv[3]);}
  if(mode=="probe"){require(argc==4,"probe args");return probe(std::stoul(argv[2]),std::stoul(argv[3]));}
  throw std::runtime_error("unknown mode");
}catch(const std::exception &e){std::cerr<<e.what()<<'\n';return 2;}
