#include <capstone/capstone.h>
#include <dlfcn.h>
#ifndef RTLD_FIRST
#define RTLD_FIRST 0
#endif
#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <stdexcept>
#include <vector>
struct API {
  decltype(&cs_open) open;
  decltype(&cs_close) close;
  decltype(&cs_option) option;
  decltype(&cs_malloc) alloc;
  decltype(&cs_free) free;
  decltype(&cs_disasm_iter) iter;
  explicit API(const char *path) {
    void *lib = dlopen(path, RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!lib) throw std::runtime_error(dlerror());
#define LOAD(field, symbol) field=reinterpret_cast<decltype(field)>(dlsym(lib,#symbol)); if(!field) throw std::runtime_error(#symbol)
    LOAD(open,cs_open); LOAD(close,cs_close); LOAD(option,cs_option);
    LOAD(alloc,cs_malloc); LOAD(free,cs_free); LOAD(iter,cs_disasm_iter);
#undef LOAD
  }
};
int main(int argc, char **argv) { try {
  if(argc!=3 && argc!=4) throw std::runtime_error("base new [invert]");
  API a(argv[1]), b(argv[2]);
  const std::vector<std::vector<uint8_t>> inputs={
    {0x83,0xc0,0xff}, {0x8b,0x40,0xfc}, {0x6a,0xff},
    {0x48,0xc7,0xc0,0xff,0xff,0xff,0xff},
    {0xb8,0xff,0xff,0xff,0xff}, {0x66,0x83,0xe8,0x80},
    {0x48,0x8b,0x84,0x88,0x00,0x00,0x00,0x80},
    {0x6b,0xc0,0xf0}, {0x67,0x8b,0x80,0xff,0xff,0xff,0xff},
    {0xe8,0xfc,0xff,0xff,0xff}, {0xf0,0x83,0x00,0xff},
    {0xc5,0xf9,0x70,0xc0,0xff}, {0x0f,0x0b}, {0x90}
  };
  struct Config { cs_arch arch; cs_mode mode; std::vector<std::vector<uint8_t>> inputs; std::vector<size_t> syntaxes; };
  std::vector<Config> configs;
  for(cs_mode mode:{CS_MODE_16,CS_MODE_32,CS_MODE_64})
    configs.push_back({CS_ARCH_X86,mode,inputs,{CS_OPT_SYNTAX_INTEL,CS_OPT_SYNTAX_ATT,CS_OPT_SYNTAX_MASM}});
  configs.push_back({CS_ARCH_AARCH64,cs_mode(0),{{0x00,0x00,0x80,0x92},{0x20,0xc0,0x5f,0xf8}},{CS_OPT_SYNTAX_DEFAULT}});
  configs.push_back({CS_ARCH_ARM,CS_MODE_ARM,{{0x04,0x00,0x11,0xe5},{0x01,0x00,0x50,0xe2}},{CS_OPT_SYNTAX_DEFAULT}});
  configs.push_back({CS_ARCH_MIPS,CS_MODE_MIPS32,{{0xff,0xff,0x02,0x24},{0xfc,0xff,0xa2,0x8f}},{CS_OPT_SYNTAX_DEFAULT}});
  configs.push_back({CS_ARCH_RISCV,CS_MODE_RISCV64,{{0x13,0x05,0xf0,0xff},{0x03,0x35,0xc1,0xff}},{CS_OPT_SYNTAX_DEFAULT}});
  size_t compared=0;
  for(const auto &config:configs) for(size_t syntax:config.syntaxes) {
    const cs_mode mode=config.mode;
    csh ha=0,hb=0;
    if(a.open(config.arch,mode,&ha)||b.open(config.arch,mode,&hb)) throw std::runtime_error("open");
    auto options=[&](cs_opt_type type,size_t va,size_t vb){
      if(a.option(ha,type,va)||b.option(hb,type,vb)) throw std::runtime_error("option");
    };
    options(CS_OPT_SYNTAX,syntax,syntax);
    options(CS_OPT_DETAIL,CS_OPT_ON,CS_OPT_ON);
    cs_insn *ia=a.alloc(ha),*ib=b.alloc(hb);
    if(!ia||!ib) throw std::runtime_error("alloc");
    for(unsigned pass=0;pass<3;++pass) for(unsigned flags=0;flags<8;++flags) {
      const bool detail=flags&2, text=!(flags&4), un=bool(flags&1)^(pass==1);
      options(CS_OPT_DETAIL,detail?CS_OPT_ON:CS_OPT_OFF,detail?CS_OPT_ON:CS_OPT_OFF);
      options(CS_OPT_TEXT,text?CS_OPT_ON:CS_OPT_OFF,text?CS_OPT_ON:CS_OPT_OFF);
      options(CS_OPT_UNSIGNED,un?CS_OPT_ON:CS_OPT_OFF,(un^(argc==4))?CS_OPT_ON:CS_OPT_OFF);
      for(const auto &bytes:config.inputs) for(size_t offset=0;offset<bytes.size();++offset)
      for(size_t length=1;length<=bytes.size()-offset;++length) {
        const uint8_t *ca=bytes.data()+offset,*cb=ca;
        size_t la=length,lb=length;uint64_t aa=0x100000,ab=aa;
        std::memset(ia->detail,0,sizeof(cs_detail));std::memset(ib->detail,0,sizeof(cs_detail));
        bool oa=a.iter(ha,&ca,&la,&aa,ia),ob=b.iter(hb,&cb,&lb,&ab,ib);
        bool same=oa==ob && ca==cb && la==lb && aa==ab;
        if(oa && ob) {
          same &= ia->id==ib->id && ia->size==ib->size && ia->address==ib->address;
          same &= !std::memcmp(ia->bytes,ib->bytes,std::min<size_t>(ia->size,sizeof(ia->bytes)));
          same &= !std::memcmp(ia->mnemonic,ib->mnemonic,sizeof(ia->mnemonic));
          same &= !std::memcmp(ia->op_str,ib->op_str,sizeof(ia->op_str));
          if(detail) {
            size_t extent=0;
            switch(config.arch) {
              case CS_ARCH_X86: extent=offsetof(cs_detail,x86)+sizeof(cs_x86); break;
              case CS_ARCH_AARCH64: extent=offsetof(cs_detail,aarch64)+sizeof(cs_aarch64); break;
              case CS_ARCH_ARM: extent=offsetof(cs_detail,arm)+sizeof(cs_arm); break;
              case CS_ARCH_MIPS: extent=offsetof(cs_detail,mips)+sizeof(cs_mips); break;
              case CS_ARCH_RISCV: extent=offsetof(cs_detail,riscv)+sizeof(cs_riscv); break;
              default: throw std::runtime_error("detail extent");
            }
            same &= !std::memcmp(ia->detail,ib->detail,extent);
          }
        }
        if(!same) { std::fprintf(stderr,"option state mismatch mode=%u syntax=%zu flags=%u pass=%u offset=%zu length=%zu\n",unsigned(mode),syntax,flags,pass,offset,length); return 42; }
        ++compared;
      }
    }
    a.free(ia,1);b.free(ib,1);a.close(&ha);b.close(&hb);
  }
  std::printf("{\"compared\":%zu}\n",compared);return 0;
} catch(const std::exception &e) { std::fprintf(stderr,"%s\n",e.what());return 1; } }
