#include <capstone/capstone.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>

struct Api {
  void *lib;
  decltype(&cs_open) open;
  decltype(&cs_close) close;
  decltype(&cs_option) option;
  decltype(&cs_disasm) decode;
  decltype(&cs_free) release;
  decltype(&cs_errno) error;
  explicit Api(const char *name) : lib(dlopen(name, RTLD_NOW | RTLD_LOCAL)) {
    if (!lib) std::abort();
    load(open, "cs_open"); load(close, "cs_close"); load(option, "cs_option");
    load(decode, "cs_disasm"); load(release, "cs_free"); load(error, "cs_errno");
  }
  template<class T> void load(T &f, const char *name) {
    f = reinterpret_cast<T>(dlsym(lib, name)); if (!f) std::abort();
  }
};
using Event = std::array<size_t,2>;
static size_t skip(const uint8_t *, size_t size, size_t off, void *user) {
  static_cast<std::vector<Event> *>(user)->push_back({size, off});
  return std::min(size - off, (off & 3) + 1);
}
int main(int argc, char **argv) {
  if (argc != 3) return 2;
  Api api[] = {Api(argv[1]), Api(argv[2])};
  size_t page = sysconf(_SC_PAGESIZE);
  auto *buf = static_cast<uint8_t *>(mmap(nullptr, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0));
  if (buf == MAP_FAILED || mprotect(buf + page, page, PROT_NONE)) return 2;
  std::vector<uint8_t> bytes;
  for (unsigned op = 0x70; op <= 0x7f; ++op) {
    const uint8_t data[] = {uint8_t(op),0x80,0x0f,uint8_t(op+16),0xff,0x78,0xed,0x04,
       0xe8,0x90,0xff,0xff,0xff,0xeb,0xf9,0xe9,0x80,0x90,0x04,0x12,
       0x66,0xe9,0xeb,0xfe,0x48,0x67,0xe8,0xff,0xff,0xff,0xff,0x0f,0xff};
    bytes.insert(bytes.end(),std::begin(data),std::end(data));
  }
  unsigned long long cases=0, instructions=0, callbacks=0;
  for (unsigned mode : {unsigned(CS_MODE_16),unsigned(CS_MODE_32),unsigned(CS_MODE_64),unsigned(CS_MODE_64|CS_MODE_X86_AMD)})
    for (unsigned syn : {CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT, CS_OPT_SYNTAX_MASM})
      for (unsigned flags=0; flags<32; ++flags) {
        csh h[2]={}; std::vector<Event> log[2]; cs_opt_skipdata setup[2]; bool supported[2];
        for (unsigned k=0;k<2;++k) {
          if(api[k].open(CS_ARCH_X86,(cs_mode)mode,&h[k])) return 2;
          supported[k]=api[k].option(h[k],CS_OPT_SYNTAX,syn)==CS_ERR_OK;
          setup[k]={".skip",skip,&log[k]};
          cs_opt_mnem mnem={X86_INS_JMP,"ourjmp"};
          if(flags&1) api[k].option(h[k],CS_OPT_DETAIL,CS_OPT_ON);
          if(flags&2) api[k].option(h[k],CS_OPT_TEXT,CS_OPT_OFF);
          if(flags&4) {
            api[k].option(h[k],CS_OPT_SKIPDATA_SETUP,(size_t)&setup[k]);
            api[k].option(h[k],CS_OPT_SKIPDATA,CS_OPT_ON);
          }
          if(flags&8) api[k].option(h[k],CS_OPT_UNSIGNED,CS_OPT_ON);
          if(flags&16) api[k].option(h[k],CS_OPT_MNEMONIC,(size_t)&mnem);
        }
        if(supported[0]!=supported[1]) return 3;
        if(supported[0]) for(size_t len : {size_t(0),size_t(1),size_t(2),size_t(3),size_t(4),size_t(5),size_t(12),size_t(33),size_t(95),bytes.size()-1,bytes.size()})
          for(size_t insns : {0,1,2,7,31,32,33,128}) for(uint64_t addr : {UINT64_C(0),UINT64_C(0xfff9),UINT64_C(0xfffffff0),UINT64_MAX-6}) {
            auto *input=buf+page-len; memcpy(input,bytes.data(),len);
            cs_insn *out[2]={};size_t n[2];cs_err e[2];
            for(unsigned k=0;k<2;k++){log[k].clear();n[k]=api[k].decode(h[k],input,len,addr,insns,&out[k]);e[k]=api[k].error(h[k]);}
            if(n[0]!=n[1]||e[0]!=e[1]||log[0]!=log[1]) return 4;
            for(size_t i=0;i<n[0];i++){
              cs_insn x=out[0][i],y=out[1][i];auto *dx=x.detail,*dy=y.detail;x.detail=y.detail=nullptr;
              if(memcmp(&x,&y,sizeof x)||bool(dx)!=bool(dy)||(dx&&memcmp(dx,dy,sizeof(*dx)))) {
                fprintf(stderr,"mode=%u syntax=%u flags=%u bytes=%zu count=%zu i=%zu id=%u/%u\n",mode,syn,flags,len,insns,i,x.id,y.id);
                return 5;
              }
            }
            ++cases;instructions+=n[0];callbacks+=log[0].size();
            for(unsigned k=0;k<2;k++)api[k].release(out[k],n[k]);
          }
        for(unsigned k=0;k<2;k++)api[k].close(&h[k]);
      }
  printf("{\"batches\":%llu,\"instructions\":%llu,\"callback_events\":%llu}\n",cases,instructions,callbacks);
  munmap(buf,page*2);
}
