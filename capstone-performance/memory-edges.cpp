#include <capstone/capstone.h>
#include <sys/mman.h>
#include <unistd.h>
#include <dlfcn.h>
#include <array>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
struct Api {
 void*lib;decltype(&cs_open) open;decltype(&cs_close) close;decltype(&cs_option) option;decltype(&cs_malloc) alloc;decltype(&cs_free) release;decltype(&cs_disasm_iter) iter;
 Api(const char*path):lib(dlopen(path,RTLD_LOCAL|RTLD_NOW)),open((decltype(open))dlsym(lib,"cs_open")),close((decltype(close))dlsym(lib,"cs_close")),option((decltype(option))dlsym(lib,"cs_option")),alloc((decltype(alloc))dlsym(lib,"cs_malloc")),release((decltype(release))dlsym(lib,"cs_free")),iter((decltype(iter))dlsym(lib,"cs_disasm_iter")){if(!lib||!iter)abort();}
};
int main(int argc,char**argv){
 Api t[]={Api(argv[1]),Api(argv[2])};size_t pg=sysconf(_SC_PAGESIZE);auto *pages=(uint8_t*)mmap(nullptr,pg*2,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANON,-1,0);if(pages==MAP_FAILED||mprotect(pages+pg,pg,PROT_NONE))return 1;
 uint64_t count=0,success=0;
 const int modes[]={0,CS_MODE_16,CS_MODE_32,CS_MODE_64,CS_MODE_64|CS_MODE_X86_AMD,CS_MODE_64|CS_MODE_X86_INTEL,CS_MODE_16|CS_MODE_32,CS_MODE_16|CS_MODE_64,CS_MODE_32|CS_MODE_64};
 for(int mode:modes)for(unsigned syntax:{CS_OPT_SYNTAX_INTEL,CS_OPT_SYNTAX_ATT,CS_OPT_SYNTAX_MASM}) for(unsigned detail=0;detail<3;detail++){
 csh h[2]={};cs_insn*i[2]={};bool usable=true;
 for(unsigned j=0;j<2;j++){if(t[j].open(CS_ARCH_X86,(cs_mode)mode,&h[j])){usable=false;continue;}if(t[j].option(h[j],CS_OPT_SYNTAX,syntax))usable=false;t[j].option(h[j],CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF);i[j]=t[j].alloc(h[j]);if(!i[j])abort();if(detail==2)t[j].option(h[j],CS_OPT_DETAIL,CS_OPT_OFF);}
 if(usable) for(unsigned form=0;form<5;form++) for(unsigned c=0;c<256;c++) for(unsigned prefix:{0u,0x67u,0x64u}) for(unsigned mod=0;mod<3;mod++) for(unsigned disp:{0x80000080u,0x7fffff7fu}) {
  uint8_t raw[16]={};unsigned n=0;if(prefix)raw[n++]=prefix;
  if(form==0)raw[n++]=0x8b;
  else if(form==1){raw[n++]=0x48;raw[n++]=0x89;}
  else if(form==2){raw[n++]=0xc5;raw[n++]=0xfc;raw[n++]=0x28;}
  else if(form==3){raw[n++]=0xc4;raw[n++]=0xe2;raw[n++]=0x75;raw[n++]=0xa8;}
  else{raw[n++]=0x62;raw[n++]=0xf3;raw[n++]=0x7d;raw[n++]=0x49;raw[n++]=0x66;}
  raw[n++]=(mod<<6)|4;raw[n++]=c;
  for(unsigned j=0;j<4;j++)raw[n++]=disp>>(8*j);
  raw[n++]=0x3f;
  for(unsigned len=0;len<=n;len++)for(uint64_t addr:{UINT64_C(0),UINT64_MAX-2}){
   uint8_t*buf=pages+pg-len;std::memcpy(buf,raw,len);size_t s[2];uint64_t a[2];const uint8_t*q[2];bool ok[2];cs_detail*d[2];
   for(unsigned j=0;j<2;j++){d[j]=i[j]->detail;if(d[j])memset(d[j],0x6b,sizeof(*d[j]));memset(i[j],0xa5,sizeof(*i[j]));i[j]->detail=d[j];s[j]=len;a[j]=addr;q[j]=buf;ok[j]=t[j].iter(h[j],&q[j],&s[j],&a[j],i[j]);}
   count++;if(ok[0])success++;cs_insn x=*i[0],y=*i[1];x.detail=y.detail=nullptr;
   if(ok[0]!=ok[1]||s[0]!=s[1]||a[0]!=a[1]||q[0]!=q[1]||memcmp(&x,&y,sizeof x)||(d[0]&&memcmp(d[0],d[1],sizeof *d[0]))){fprintf(stderr,"mode=%d syntax=%u detail=%u c=%u prefix=%x disp=%x len=%u addr=%llx good=%u/%u id=%u/%u\n",mode,syntax,detail,c,prefix,disp,len,(unsigned long long)addr,ok[0],ok[1],x.id,y.id);return 3;}
  }
 }
 for(unsigned j=0;j<2;j++){if(i[j])t[j].release(i[j],1);if(h[j])t[j].close(&h[j]);}
 }
 printf("{\"calls\":%llu,\"accepted\":%llu,\"guard_page\":true}\n",(unsigned long long)count,(unsigned long long)success);munmap(pages,2*pg);
}
