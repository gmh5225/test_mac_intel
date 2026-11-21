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

static unsigned family(const uint8_t *data, size_t size, bool long_mode) {
    while(size && (*data==0x26 || *data==0x2e || *data==0x36 || *data==0x3e ||
                  *data==0x64 || *data==0x65 || *data==0x67)) {++data; --size;}
    // In legacy modes these escapes share opcodes with LES, LDS and BOUND.
    if (size < 2 || (!long_mode && (data[1] & 0xc0) != 0xc0)) return 0;
    if(size<7 || data[0]!=0x62 || (data[1]&0xf)!=3 || (data[2]&7)!=5) return 0;
    bool wide=data[2]&128;
    switch(data[4]) {
      case 0x1e:return wide?X86_INS_VPCMPUQ:X86_INS_VPCMPUD;
      case 0x1f:return wide?X86_INS_VPCMPQ:X86_INS_VPCMPD;
      case 0x3e:return wide?X86_INS_VPCMPUW:X86_INS_VPCMPUB;
      case 0x3f:return wide?X86_INS_VPCMPW:X86_INS_VPCMPB;
    }
    return 0;
}
static unsigned floating(const uint8_t *data,size_t size, bool long_mode) {
    while(size && (*data==0x26 || *data==0x2e || *data==0x36 || *data==0x3e ||
                   *data==0x64 || *data==0x65 || *data==0x67)) {++data; --size;}
    // In legacy modes these escapes share opcodes with LES, LDS and BOUND.
    if (size < 2 || (!long_mode && (data[1] & 0xc0) != 0xc0)) return 0;
    unsigned pp;
    if(size>=5 && data[0]==0xc5 && data[2]==0xc2) pp=data[1]&3;
    else if(size>=6 && data[0]==0xc4 && (data[1]&31)==1 && data[3]==0xc2) pp=data[2]&3;
    else if(size>=7 && data[0]==0x62 && (data[1]&15)==1 && data[4]==0xc2) pp=data[2]&3;
    else return 0;
    static constexpr unsigned ids[]={X86_INS_VCMPPS,X86_INS_VCMPPD,X86_INS_VCMPSS,X86_INS_VCMPSD};
    return ids[pp];
}
static unsigned canonical(unsigned id, const uint8_t *code, size_t size, bool long_mode) {
  if(auto fp=floating(code,size,long_mode)) return fp;
  if (id != X86_INS_VPCMP) return id;
  const unsigned result = family(code,size,long_mode);
  if (!result) std::abort();
  return result;
}

int main(int argc, char **argv) {
  if (argc != 5 && argc != 6) return 2;
  std::ifstream f(argv[1], std::ios::binary);
  if (!f) return 2;
  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)), {});
  const std::string target = argv[2];
  const bool arm = target == "arm64";
  const bool a32 = target == "arm", mips = target == "mips64el";
  const int mode = std::stoi(argv[3]), repeats = std::stoi(argv[4]);
  if (bytes.empty() || (!arm && !a32 && !mips && target != "32" && target != "64") ||
      mode < 0 || mode > 3 || repeats < 1) return 2;
  if (mode == 3 && (arm || a32 || mips)) return 2;
  const auto arch = a32 ? neverd::Arch::ARM : mips ? neverd::Arch::MIPS64EL : arm ? neverd::Arch::AArch64 :
                    target == "32" ? neverd::Arch::X86 : neverd::Arch::X64;
  neverd::Decoder decoder;
  if (!decoder.init(arch)) return 3;
  decoder.setDetail(mode == 2);
  decoder.setText(mode == 1 || mode == 2);
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
          value += canonical(instructions[i] >> 8, bytes.data() + off, length, target == "64");
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
        off += (arm || a32 || mips) ? std::min<size_t>(4, left) : 1;
        continue;
      }
      if (size_t(count) > left || !insn.Raw) return 4;
      ++accepted;
      boundary = (boundary ^ ((off << 5) | unsigned(count))) * 1099511628211ull;
      value += (arm || a32 || mips) ? insn.Id : canonical(insn.Id, code, count, target == "64");
      if (mode == 1 || mode == 2) {
        value += std::strlen(insn.Raw->mnemonic) + std::strlen(insn.Raw->op_str);
      }
      if (mode == 2) {
        if (!insn.Raw->detail) return 5;
        cs_regs reads, writes;
        uint8_t nr = 0, nw = 0;
        if (cs_regs_access(decoder.getHandle(), insn.Raw, reads, &nr, writes, &nw) != CS_ERR_OK)
          return 6;
        for (unsigned i = 0; i < nr; ++i) value += reads[i];
        for (unsigned i = 0; i < nw; ++i) value += writes[i];
        value += arm ? insn.Raw->detail->aarch64.op_count : a32 ? insn.Raw->detail->arm.op_count : mips ? insn.Raw->detail->mips.op_count : insn.Raw->detail->x86.op_count;
      }
      off += size_t(count);
    }
    }
  }
  std::printf("%lld %llu %llu %llu %llu\n", (long long)(std::clock()-start),
              (unsigned long long)accepted,(unsigned long long)rejected,
              (unsigned long long)boundary,(unsigned long long)value);
}
