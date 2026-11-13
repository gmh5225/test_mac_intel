#include "neverd/decode/Decoder.h"
#include <cstdlib>
#include <array>
#include <cstdio>
#include <cstring>
#include <vector>
using namespace neverd;
static uint64_t hash=14695981039346656037ull;
static void observe(const void* data,size_t n){ const auto*b=static_cast<const uint8_t*>(data);while(n--)hash=(hash^*b++)*1099511628211ull; }
static int all_xbegin_targets() {
    unsigned count=0;
    for (auto arch : {neverd::Arch::X86,neverd::Arch::X64})
        for (bool ad : {false,true}) {
            neverd::Decoder decoder;
            if (!decoder.init(arch)) return 7;
            std::array<uint8_t,6> bytes{0x67,0x66,0xc7,0xf8,0,0};
            for (unsigned bits=0; bits<65536; ++bits) {
                bytes[4]=(uint8_t)bits; bytes[5]=(uint8_t)(bits>>8);
                const uint64_t expected=uint64_t(0x12345000+5+ad)+(int16_t)bits;
                for (unsigned route=0;route<3;++route) {
                    neverd::DecodedInsn i{};
                    auto *src=bytes.data()+!ad;size_t n=5+ad;
                    int size=route==0?decoder.decodeOne(src,n,0x12345000,i):route==1?decoder.decodeOneLight(src,n,0x12345000,i):decoder.decodeOneForLift(src,n,0x12345000,i);
                    if ((size_t)size!=n || !i.Raw || !i.Raw->detail || i.Id!=X86_INS_XBEGIN || i.Raw->detail->x86.operands[0].imm!=(int64_t)expected) return 6;
                    ++count;
                }
            }
        }
    std::printf("%u signed XBEGIN targets across three production decode routes\n",count);
    return 0;
}

static int rendered_xbegin_targets() {
  Decoder decoder;
  if (!decoder.init(Arch::X86)) return 10;
  unsigned count = 0;
  for (auto syntax : {CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT}) {
    if (cs_option(decoder.getHandle(), CS_OPT_SYNTAX, syntax) != CS_ERR_OK)
      return 11;
    for (bool detail : {false, true}) {
      decoder.setText(true);
      decoder.setDetail(detail);
      for (bool address_prefix : {false, true}) for (bool rel16 : {false, true})
        for (uint32_t bits : {0u, 1u, 0xffffu, 0x7fffu, 0x8000u,
                              0x34128000u, 0x80000000u, 0xffffffffu}) {
          std::array<uint8_t, 8> bytes{};
          size_t n = 0;
          if (address_prefix) bytes[n++] = 0x67;
          if (rel16) bytes[n++] = 0x66;
          bytes[n++] = 0xc7;
          bytes[n++] = 0xf8;
          for (unsigned j = 0; j < (rel16 ? 2u : 4u); ++j)
            bytes[n++] = static_cast<uint8_t>(bits >> (8 * j));
          uint32_t displacement = bits;
          if (rel16)
            displacement = (bits & 0xffffu) | ((bits & 0x8000u) ? 0xffff0000u : 0u);
          for (uint32_t ip : {0u, 0x1000u, 0xfffffffbu, 0xffffffffu})
            for (unsigned route = 0; route < 3; ++route) {
              DecodedInsn insn{};
              int length = route == 0 ? decoder.decodeOne(bytes.data(), n, ip, insn)
                         : route == 1 ? decoder.decodeOneLight(bytes.data(), n, ip, insn)
                                      : decoder.decodeOneForLift(bytes.data(), n, ip, insn);
              if (length != static_cast<int>(n) || !insn.Raw || insn.Id != X86_INS_XBEGIN)
                return 12;
              char *end = nullptr;
              const char *operand = insn.Raw->op_str;
              uint32_t expected = ip + static_cast<uint32_t>(n) + displacement;
              if (!*operand || std::strtoull(operand, &end, 0) != expected || *end ||
                  (detail && (!insn.Raw->detail || insn.Raw->detail->x86.op_count != 1 ||
                   insn.Raw->detail->x86.operands[0].type != X86_OP_IMM ||
                   static_cast<uint64_t>(insn.Raw->detail->x86.operands[0].imm) != expected))) {
                std::fprintf(stderr, "syntax=%u detail=%u address-prefix=%u rel16=%u bits=%x ip=%x route=%u expected=%x operand=%s\n",
                             unsigned(syntax), detail, address_prefix, rel16, bits, ip, route, expected, operand);
                return 13;
              }
              ++count;
            }
        }
    }
  }
  std::printf("%u rendered i386 targets checked across text-only and text+detail\n", count);
  return 0;
}

int main(int argc,char**argv) {
  if(argc==2 && std::strcmp(argv[1],"--rendered-xbegin")==0)return rendered_xbegin_targets();
  if(argc==2 && std::strcmp(argv[1],"--xbegin")==0)return all_xbegin_targets();
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
