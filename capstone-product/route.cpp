#include "neverd/decode/Decoder.h"
#include <array>
#include <cstdio>
#include <cstring>
#include <vector>
using namespace neverd;
static uint64_t hash=14695981039346656037ull;
static void observe(const void* data,size_t n){ const auto*b=static_cast<const uint8_t*>(data);while(n--)hash=(hash^*b++)*1099511628211ull; }
int main(int argc,char**argv) {
  FILE* trace=argc>1?std::fopen(argv[1],"wb"):nullptr;
  if(argc>1&&!trace)return 5;
  if(trace) {
    uint32_t meta[]={sizeof(cs_insn),sizeof(cs_detail),offsetof(cs_detail,x86),sizeof(cs_x86),offsetof(cs_x86,operands),sizeof(cs_x86_op),offsetof(cs_insn,mnemonic),offsetof(cs_insn,op_str),offsetof(cs_insn,detail)};
    std::fwrite(meta,sizeof(meta),1,trace);
  }
  Decoder d;size_t samples=0;
  for(auto arch:{Arch::X86,Arch::X64,Arch::X86}) {
    if(!d.init(arch))return 1;
    const std::vector<std::vector<uint8_t>> enc={{0x90},{0x48,0x89,0xd9},{0x0f,0x1a,0xc8},{0xf2,0x0f,0x1a,0x45,0x80},{0x67,0xf2,0x0f,0x1a,0x44,0x93,4},{0xf0,0x0f,0x1b,0x40,8},{0x66,0x66,0x0f,0xae,0xe8},{0x66,0x8b,0x85,0,0,0,0x80},{0x67,0x66,0x8b,0x85,0xff,0xff,0xff,0x7f},{0xc7,0xf8,0xfe,0xff,0x00,0x80},{0x66,0xc7,0xf8,0,0x80},{0x67,0xc7,0xf8,0,0x80,0x12,0x34},{0xeb,0xfe},{0xe8,0xfe,0xff,0xff,0xff},{0x0f,0x85,0,0,0,0x80},{0x8b,0x58,0xf8},{0x62,0xf2,0x7d,0x48,0xdc,0xc1},{0x0f,0x0b},{0x62}};
    const uint8_t nop=0x90;DecodedInsn warm{};
    if(!d.decodeOne(&nop,1,0x1000,warm)||!warm.Raw||!warm.Raw->detail)return 2;
    auto *record=const_cast<cs_insn*>(warm.Raw);auto *detail=record->detail;
    for(unsigned flags:{3,0,2,1,3,0,3}) {
      d.setText(flags&1);d.setDetail(flags&2);
      for (auto syntax:{CS_OPT_SYNTAX_INTEL,CS_OPT_SYNTAX_ATT}) {
        if(cs_option(d.getHandle(),CS_OPT_SYNTAX,syntax)!=CS_ERR_OK)return 3;
        for(unsigned route=0;route<3;++route) for(auto &bytes:enc)
          for(size_t size=0;size<=bytes.size();++size)
            for(uint64_t ip:{0x1000ull,0xfffffff0ull,0xfffffffffffffffcull}) {
              const auto seed=static_cast<int>(size+flags+ip);
              std::memset(record,seed,sizeof(*record));std::memset(detail,seed,sizeof(*detail));record->detail=detail;
              record->is_alias=false;record->usesAliasDetails=false;record->illegal=false;
              DecodedInsn out{};int length=route==0?d.decodeOne(bytes.data(),size,ip,out):route==1?d.decodeOneLight(bytes.data(),size,ip,out):d.decodeOneForLift(bytes.data(),size,ip,out);
              observe(&length,sizeof(length));
              if(length){if(!out.Raw||out.Raw!=record||out.Raw->detail!=detail)return 4;observe(&out.Id,sizeof(out.Id));observe(&out.Addr,sizeof(out.Addr));}
              record->detail=nullptr;
              if(trace){uint32_t id[]={unsigned(arch),flags,unsigned(syntax),route,unsigned(&bytes-&enc.front()),unsigned(size),unsigned(ip),unsigned(length)};
               std::fwrite(id,sizeof(id),1,trace);std::fwrite(record,sizeof(*record),1,trace);std::fwrite(detail,sizeof(*detail),1,trace);}
              observe(record,sizeof(*record));observe(detail,sizeof(*detail));record->detail=detail;++samples;
            }
      }
    }
  }
  if(trace)std::fclose(trace);
  std::printf("%zu %llu\n",samples,(unsigned long long)hash);return 0;
}
