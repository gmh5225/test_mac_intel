// Development-only cache-free graph adapter. Never loads target code.
#if defined(__APPLE__)
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/sha.h>
using CC_LONG = size_t;
#define CC_SHA256_DIGEST_LENGTH SHA256_DIGEST_LENGTH
#define CC_SHA256 SHA256
#endif
#include <algorithm>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>
namespace fs=std::filesystem;
using Bytes=std::vector<unsigned char>;
void require(bool ok,const std::string&s){if(!ok)throw std::runtime_error(s);}
std::string hash(const unsigned char*p,size_t n){unsigned char digest[CC_SHA256_DIGEST_LENGTH];CC_SHA256(p,CC_LONG(n),digest);const char*x="0123456789abcdef";std::string s;for(auto c:digest){s+=x[c>>4];s+=x[c&15];}return s;}
Bytes bytes(const fs::path&p){require(!fs::is_symlink(fs::symlink_status(p))&&fs::is_regular_file(p),"nonregular input");require(fs::file_size(p)<=512*1024*1024,"file budget");std::ifstream f(p,std::ios::binary);Bytes b((std::istreambuf_iterator<char>(f)),{});require(bool(f)||f.eof(),"read input");return b;}
void write(const fs::path&p,const Bytes&b){require(!fs::exists(p),"fresh output required");std::ofstream f(p,std::ios::binary);f.write(reinterpret_cast<const char*>(b.data()),b.size());require(bool(f),"write output");}
uint64_t number(const Bytes&b,uint64_t p,unsigned n){require(n<=8&&p<=b.size()&&n<=b.size()-p,"integer range");uint64_t r=0;for(unsigned j=0;j<n;j++)r|=uint64_t(b[p+j])<<(j*8);return r;}
void set(Bytes&b,uint64_t p,uint64_t n,unsigned width){require(p<=b.size()&&width<=b.size()-p,"write range");for(unsigned j=0;j<width;j++)b[p+j]=(n>>(j*8))&255;}
std::string text(const Bytes&b,uint64_t p,uint64_t n){require(p<=b.size()&&n<=b.size()-p,"text range");return std::string(b.begin()+p,b.begin()+p+n);}
std::string lower(std::string s){for(auto&c:s)c=char(std::tolower(static_cast<unsigned char>(c)));return s;}
std::string portable(const std::string&s){
 require(!s.empty()&&s.size()<=4096&&s.front()!='/'&&s.back()!='/',"unsafe relative path");
 std::stringstream in(s);std::string part;
 while(std::getline(in,part,'/')){
  require(!part.empty()&&part.size()<=255&&part!="."&&part!=".."&&part.back()!='.',"unsafe component");
  for(unsigned char c:part)require((c>='A'&&c<='Z')||(c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='_'||c=='-'||c=='.',"nonportable component");
  auto stem=lower(part.substr(0,part.find('.')));
  require(stem!="con"&&stem!="prn"&&stem!="aux"&&stem!="nul"&&!(stem.size()==4&&(stem.starts_with("com")||stem.starts_with("lpt"))&&stem[3]>='0'&&stem[3]<='9'),"reserved component");
 }
 return s;
}
uint64_t decimal(const std::string&s){require(!s.empty()&&std::all_of(s.begin(),s.end(),[](char c){return c>='0'&&c<='9';}),"decimal");return std::stoull(s);}
struct Row{std::string name,suffix,file,sha;unsigned loader,encoding,format,side;uint64_t size;};
std::vector<Row> mapping(const fs::path&p){
 std::ifstream in(p);require(bool(in),"map input");std::string line;std::vector<Row> rows;std::set<std::string> files,dirs;
 while(std::getline(in,line)){
  require(line.size()<32768&&rows.size()<20000,"map budget");std::stringstream ss(line);std::string field;std::vector<std::string> f;while(std::getline(ss,field,'\t'))f.push_back(field);require(f.size()==8,"map fields");
  require(f[0].starts_with("/$bunfs/root/"),"virtual prefix");Row r;r.name=f[0];r.suffix=portable(f[0].substr(13));r.loader=decimal(f[1]);r.encoding=decimal(f[2]);r.format=decimal(f[3]);r.side=decimal(f[4]);r.file=portable(f[5]);r.size=decimal(f[6]);r.sha=f[7];
  require(r.size<=512*1024*1024&&r.sha.size()==64&&std::all_of(r.sha.begin(),r.sha.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');}),"map size/hash");
  require((r.loader==1&&r.encoding<=2&&r.format==1&&r.side==0)||(r.loader==13&&r.encoding<=2&&r.format==0&&r.side<=1)||((r.loader==5||r.loader==10)&&r.encoding==0&&r.format==0&&r.side==1),"unqualified record type");
  if(r.encoding==2&&r.loader==13)require(r.size%2==0,"UTF16 odd size");
  auto key=lower(r.suffix);require(key!="client"&&key!="bootstrap.mjs"&&key!="build.isolated.mjs","reserved scaffold collision");require(!files.contains(key)&&!dirs.contains(key),"duplicate/file-dir collision");
  for(size_t pos=key.find('/');pos!=std::string::npos;pos=key.find('/',pos+1)){auto parent=key.substr(0,pos);require(!files.contains(parent),"file-dir collision");dirs.insert(parent);}
  files.insert(key);rows.push_back(std::move(r));
 }
 require(!rows.empty(),"empty map");return rows;
}
void stage(const std::vector<Row>&rows,const fs::path&source,const fs::path&out){
 require(!fs::exists(out),"fresh graph directory required");fs::create_directory(out);
 for(const auto&r:rows){auto b=bytes(source/r.file);require(b.size()==r.size&&hash(b.data(),b.size())==r.sha,"source body hash");if(r.loader==13)b.insert(b.end(),3,0);auto p=out/r.suffix;fs::create_directories(p.parent_path());write(p,b);std::cout<<"{\"name\":\""<<r.name<<"\",\"sha256\":\""<<r.sha<<"\",\"logical_bytes\":"<<r.size<<",\"staged_bytes\":"<<b.size()<<"}\n";}
}
#include "native-graph-location.h"
void patch(const std::vector<Row>&rows,const fs::path&source,const fs::path&out){
 auto b=bytes(source);const auto native=locateNativeGraph(b);auto g=native.base,gs=native.size;auto f=g+gs-48;require(text(b,f+32,16)=="\n---- Bun! ----\n"&&number(b,f,8)==gs-48,"footer");auto table=number(b,f+8,4),length=number(b,f+12,4),flags=number(b,f+28,4);require(length==(rows.size()+1)*52&&table+length<=gs-48&&flags==0x17c&&number(b,f+16,4)==0,"unqualified cache-free graph");
 auto modules=length/52,tail=table+length;require(number(b,g+tail+modules*4,4)==0,"builtin cache");require(number(b,f+20,4)==tail+modules*4+8,"optional cache metadata");
 std::map<std::string,const Row*> expected;for(const auto&r:rows)expected.emplace(r.name,&r);std::set<std::string> seen;unsigned patched=0;
 for(uint64_t index=0;index<modules;index++){
  auto at=g+table+index*52;auto no=number(b,at,4),nn=number(b,at+4,4),co=number(b,at+8,4),cn=number(b,at+12,4);require(no+nn+1<=table&&co+cn+1<=table,"payload range");require(b[g+no+nn]==0&&b[g+co+cn]==0,"terminators");auto name=text(b,g+no,nn);require(seen.insert(name).second,"duplicate graph name");for(unsigned off=16;off<48;off+=4)require(number(b,at+off,4)==0,"source-map/cache metadata refused");
  if(index==0){require(name=="/$bunfs/root/client"&&b[at+48]==1&&b[at+49]==1&&b[at+50]==1&&b[at+51]==0,"bootstrap profile");continue;}
  auto found=expected.find(name);require(found!=expected.end(),"unexpected embedded file");const auto&r=*found->second;require(b[at+48]==0&&b[at+49]==5&&b[at+50]==0&&b[at+51]==1,"raw asset profile");require(cn==r.size+(r.loader==13?3:0)&&hash(b.data()+g+co,r.size)==r.sha,"embedded raw hash");
  if(r.loader!=13)continue;
  require(number(b,g+tail+index*4,4)==0,"raw text hash not zero");for(uint64_t j=r.size;j<cn;j++)require(b[g+co+j]==0,"text reserved padding");auto shift=r.encoding==2?(co&1):0;auto originalCo=co;
  if(shift)std::memmove(b.data()+g+co+shift,b.data()+g+co,r.size);
  co+=shift;b[g+co+r.size]=0;b[g+co+r.size+1]=0;if(shift)b[g+originalCo]=0;
  set(b,at+8,co,4);set(b,at+12,r.size,4);b[at+48]=r.encoding;b[at+49]=13;b[at+50]=0;b[at+51]=r.side;
  require(hash(b.data()+g+co,r.size)==r.sha,"patched body hash");require(r.encoding!=2||((co|r.size)&1)==0,"UTF16 alignment");
  ++patched;std::cout<<"{\"name\":\""<<name<<"\",\"body_sha256\":\""<<r.sha<<"\",\"body_bytes\":"<<r.size<<",\"encoding\":"<<r.encoding<<",\"side\":"<<r.side<<",\"shift\":"<<shift<<",\"body_offset\":"<<co<<",\"terminator_bytes\":2}\n";
 }
 require(seen.size()==rows.size()+1&&patched==std::count_if(rows.begin(),rows.end(),[](const Row&r){return r.loader==13;}),"missing records");write(out,b);
}
int main(int argc,char**argv)try{require(argc==5,"stage|patch map input output");auto rows=mapping(argv[2]);if(std::string(argv[1])=="stage")stage(rows,argv[3],argv[4]);else if(std::string(argv[1])=="patch")patch(rows,argv[3],argv[4]);else throw std::runtime_error("mode");return 0;}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}
