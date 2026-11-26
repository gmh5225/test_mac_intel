#include "neverd/decode/Decoder.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

static unsigned integer_family(const uint8_t *p,size_t n) {
    while(n && (*p==0x26||*p==0x2e||*p==0x36||*p==0x3e||*p==0x64||*p==0x65||*p==0x67)){++p;--n;}
    if(n<7||p[0]!=0x62||(p[1]&15)!=3||(p[2]&7)!=5)return 0;
    bool wide=(p[2]&128)!=0;
    switch(p[4]){
        case 0x1e:return wide?X86_INS_VPCMPUQ:X86_INS_VPCMPUD;
        case 0x1f:return wide?X86_INS_VPCMPQ:X86_INS_VPCMPD;
        case 0x3e:return wide?X86_INS_VPCMPUW:X86_INS_VPCMPUB;
        case 0x3f:return wide?X86_INS_VPCMPW:X86_INS_VPCMPB;
        default:return 0;
    }
}
static bool floating_compare(const uint8_t *p,size_t n) {
    while(n && (*p==0x26||*p==0x2e||*p==0x36||*p==0x3e||*p==0x64||*p==0x65||*p==0x67)){++p;--n;}
    return (n>=5&&p[0]==0xc5&&p[2]==0xc2)||(n>=6&&p[0]==0xc4&&(p[1]&31)==1&&p[3]==0xc2)||
           (n>=7&&p[0]==0x62&&(p[1]&15)==1&&p[4]==0xc2);
}

static csh canonical;
static uint64_t projected, typed, integers;
static int64_t correction;
static bool lifted_detail;
static unsigned compare_width(const uint8_t *p,size_t n) {
  while(n && (*p==0x26||*p==0x2e||*p==0x36||*p==0x3e||*p==0x64||*p==0x65||*p==0x67)){++p;--n;}
  const unsigned pp = p[p[0] == 0xc5 ? 1 : 2] & 3;
  const unsigned width[] = {X86_INS_VCMPPS,X86_INS_VCMPPD,X86_INS_VCMPSS,X86_INS_VCMPSD};
  return width[pp];
}
static unsigned reference_id(unsigned old, const uint8_t *code, size_t length, uint64_t ip) {
  if (!canonical) return old;
  if (unsigned family=integer_family(code,length)) {
    const unsigned raw=old;
    cs_insn *bulk=nullptr;
    const size_t n=cs_disasm(canonical,code,length,ip,1,&bulk);
    if (!n || bulk->size!=length) std::exit(12);
    const unsigned bulk_id=bulk->id;
    cs_free(bulk,n);
    if (bulk_id!=family) {
      // A legacy 32-bit BOUND can share the leading EVEX bytes.
      if (bulk_id==X86_INS_BOUND && raw==bulk_id) return old;
      std::exit(13);
    }
    if (raw!=X86_INS_VPCMP && raw!=family) std::exit(14);
    if (raw!=family) { ++integers; correction+=int64_t(family)-raw; }
    return family;
  }
  if (!floating_compare(code,length)) return old;
  cs_insn *result = nullptr;
  size_t count = cs_disasm(canonical,code,length,ip,1,&result);
  unsigned wanted = old;
  if (count && result->size == length && result->id == X86_INS_VCMP && lifted_detail) {
    const unsigned expected=compare_width(code,length);
    if(old!=expected) {std::fprintf(stderr,"address=%llx width=%u observed=%u\\n",(unsigned long long)ip,expected,old);std::exit(10);}
    ++typed;
  } else if (count && result->size == length && result->id == X86_INS_VCMP && old != result->id) {
    if (old != result->id + 1 + (code[length-1]&31)) std::exit(9);
    wanted = result->id;
    projected++;
    correction+=int64_t(wanted)-old;
  }
  cs_free(result,count);
  return wanted;
}

int main(int argc, char **argv) {
  if (argc != 5 && argc != 6) return 2;
  std::ifstream f(argv[1], std::ios::binary);
  if (!f) return 2;
  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)), {});
  const std::string target = argv[2];
  const bool arm = target == "arm64";
  const bool a32 = target == "arm", mips = target == "mips64el";
  const bool riscv = target == "riscv64", ppc = target == "ppc64el";
  const int setting = std::stoi(argv[3]), repeats = std::stoi(argv[4]);
  if (setting < 0 || setting > 5) return 2;
  const bool att = setting >= 4;
  const int mode = att ? setting - 3 : setting;
  if (bytes.empty() || (!arm && !a32 && !mips && !ppc && !riscv && target != "32" && target != "64") ||
      mode < 0 || mode > 3 || repeats < 1) return 2;
  if (mode == 3 && (arm || a32 || mips || ppc || riscv)) return 2;
  const auto arch = riscv ? neverd::Arch::RISCV64 : ppc ? neverd::Arch::PPC64LE : a32 ? neverd::Arch::ARM : mips ? neverd::Arch::MIPS64EL : arm ? neverd::Arch::AArch64 :
                    target == "32" ? neverd::Arch::X86 : neverd::Arch::X64;
  neverd::Decoder decoder;
  if (!decoder.init(arch)) return 3;
  if (riscv) {
    neverd::BinaryImage image;
    image.Arch = arch;
    image.RISCV.Multiply = image.RISCV.Atomic = image.RISCV.Compressed = true;
    decoder.configureFor(image);
  }
  if ((target == "32" || target == "64") && cs_open(CS_ARCH_X86,target=="32"?CS_MODE_32:CS_MODE_64,&canonical)) return 9;
  lifted_detail=mode==2;
  decoder.setDetail(mode == 2);
  decoder.setText(mode == 1 || mode == 2);
  if (att && ((target != "32" && target != "64") ||
              cs_option(decoder.getHandle(), CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT) != CS_ERR_OK))
    return 8;
  struct Span { size_t start, size; uint64_t address; };
  std::vector<Span> spans{{0, bytes.size(), 0x100000}};
  if (argc == 6) {
    std::ifstream input(argv[5]);
    if (!input) return 2;
    spans.clear();
    Span span;
    while (input >> span.start) {
      if (!(input >> span.size >> span.address) || !span.size ||
          span.start > bytes.size() || span.size > bytes.size()-span.start) return 2;
      spans.push_back(span);
    }
    if (!input.eof() || spans.empty()) return 2;
  }
  uint64_t accepted = 0, rejected = 0, value = 0, boundary = 14695981039346656037ull;
  const auto start = std::clock();
  for (int rep = 0; rep < repeats; ++rep) {
    for (const Span &span : spans) {
    for (size_t off = span.start; off < span.start+span.size;) {
      auto code = bytes.data() + off;
      auto left = span.start+span.size - off;
      if (mode == 3) {
        // X86CallScan uses this same 64-instruction prefix and falls back to
        // decodeOneLight when the physical classifier stops.
        uint32_t instructions[64];
        const size_t count = decoder.classifyX86Prefix(
            {code, left}, span.address + off-span.start, instructions);
        if (count > 64) return 7;
        for (size_t i = 0; i < count; ++i) {
          const unsigned length = instructions[i] & 255;
          if (!length || length > left || !(instructions[i] >> 8)) return 4;
          ++accepted;
          boundary = (boundary ^ ((off << 5) | length)) * 1099511628211ull;
          value += reference_id(instructions[i] >> 8, bytes.data()+off, length, span.address+off-span.start);
          off += length;
          left -= length;
        }
        if (count) continue;
      }
      neverd::DecodedInsn insn{};
      int count = mode == 2 ? decoder.decodeOne(code, left, span.address + off-span.start, insn)
                            : decoder.decodeOneLight(code, left, span.address + off-span.start, insn);
      if (count <= 0) {
        ++rejected;
        boundary = (boundary ^ off) * 1099511628211ull;
        off += (arm || a32 || mips || ppc) ? std::min<size_t>(4, left) : riscv ? std::min<size_t>(2, left) : 1;
        continue;
      }
      if (size_t(count) > left || !insn.Raw) return 4;
      ++accepted;
      boundary = (boundary ^ ((off << 5) | unsigned(count))) * 1099511628211ull;
      value += reference_id(insn.Id,code,count,span.address+off-span.start);
      if (mode == 1 || mode == 2) {
        value += std::strlen(insn.Raw->mnemonic) + std::strlen(insn.Raw->op_str);
      }
      if (mode == 2) {
        if (!insn.Raw->detail) return 5;
        cs_regs reads, writes;
        uint8_t nr = 0, nw = 0;
        const cs_err result = cs_regs_access(decoder.getHandle(), insn.Raw, reads, &nr, writes, &nw);
        if (ppc && result == CS_ERR_ARCH) {
          for (unsigned i=0;i<insn.Raw->detail->regs_read_count;++i) value+=insn.Raw->detail->regs_read[i];
          for (unsigned i=0;i<insn.Raw->detail->regs_write_count;++i) value+=insn.Raw->detail->regs_write[i];
        } else if (result != CS_ERR_OK) return 6;
        for (unsigned i = 0; i < nr; ++i) value += reads[i];
        for (unsigned i = 0; i < nw; ++i) value += writes[i];
        value += ppc ? insn.Raw->detail->ppc.op_count : riscv ? insn.Raw->detail->riscv.op_count : arm ? insn.Raw->detail->aarch64.op_count : a32 ? insn.Raw->detail->arm.op_count : mips ? insn.Raw->detail->mips.op_count : insn.Raw->detail->x86.op_count;
      }
      off += size_t(count);
    }
    }
  }
  if (canonical) cs_close(&canonical);
  std::fprintf(stderr, "%llu %llu %llu %lld\n", static_cast<unsigned long long>(projected), static_cast<unsigned long long>(typed), static_cast<unsigned long long>(integers), static_cast<long long>(correction));
  std::printf("%lld %llu %llu %llu %llu\n", (long long)(std::clock()-start),
              (unsigned long long)accepted,(unsigned long long)rejected,
              (unsigned long long)boundary,(unsigned long long)value);
}
