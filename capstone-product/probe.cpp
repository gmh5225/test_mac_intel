#include "neverd/decode/Decoder.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <chrono>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

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
  const auto wall_start = std::chrono::steady_clock::now();
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
          value += instructions[i] >> 8;
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
      value += insn.Id;
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
  const auto cpu = std::clock()-start;
  const auto elapsed = std::chrono::steady_clock::now() - wall_start;
  std::printf("%lld %llu %llu %llu %llu\n", (long long)cpu,
              (unsigned long long)accepted,(unsigned long long)rejected,
              (unsigned long long)boundary,(unsigned long long)value);
  if (std::getenv("NEVERD_PROBE_BOTH_CLOCKS"))
    std::printf("%lld\n", (long long)std::chrono::duration_cast<std::chrono::nanoseconds>(elapsed).count());
}
