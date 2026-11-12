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

int main(int argc, char **argv) {
  if (argc != 5) return 2;
  std::ifstream f(argv[1], std::ios::binary);
  if (!f) return 2;
  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)), {});
  const std::string target = argv[2];
  const bool arm = target == "arm64";
  const int mode = std::stoi(argv[3]), repeats = std::stoi(argv[4]);
  if (bytes.empty() || (!arm && target != "32" && target != "64") ||
      mode < 0 || mode > 2 || repeats < 1) return 2;
  const auto arch = arm ? neverd::Arch::AArch64 :
                    target == "32" ? neverd::Arch::X86 : neverd::Arch::X64;
  neverd::Decoder decoder;
  if (!decoder.init(arch)) return 3;
  decoder.setDetail(mode == 2);
  decoder.setText(mode != 0);
  uint64_t accepted = 0, rejected = 0, value = 0, boundary = 14695981039346656037ull;
  const auto start = std::clock();
  for (int rep = 0; rep < repeats; ++rep) {
    for (size_t off = 0; off < bytes.size();) {
      neverd::DecodedInsn insn{};
      auto code = bytes.data() + off;
      auto left = bytes.size() - off;
      int count = mode == 2 ? decoder.decodeOne(code, left, 0x100000 + off, insn)
                            : decoder.decodeOneLight(code, left, 0x100000 + off, insn);
      if (count <= 0) {
        ++rejected;
        boundary = (boundary ^ off) * 1099511628211ull;
        off += arm ? std::min<size_t>(4, left) : 1;
        continue;
      }
      if (size_t(count) > left || !insn.Raw) return 4;
      ++accepted;
      boundary = (boundary ^ ((off << 5) | unsigned(count))) * 1099511628211ull;
      value += insn.Id;
      if (mode) {
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
        value += arm ? insn.Raw->detail->aarch64.op_count : insn.Raw->detail->x86.op_count;
      }
      off += size_t(count);
    }
  }
  std::printf("%lld %llu %llu %llu %llu\n", (long long)(std::clock()-start),
              (unsigned long long)accepted,(unsigned long long)rejected,
              (unsigned long long)boundary,(unsigned long long)value);
}
