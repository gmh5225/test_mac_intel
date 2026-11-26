#include <capstone/capstone.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

int main(int argc, char **argv) {
  if (argc != 5) return 1;
  const std::string target = argv[1];
  const unsigned output = std::stoul(argv[3]), repeats = std::stoul(argv[4]);
  cs_arch arch;
  cs_mode mode;
  if (target == "arm64") { arch = CS_ARCH_AARCH64; mode = CS_MODE_LITTLE_ENDIAN; }
  else if (target == "arm") { arch = CS_ARCH_ARM; mode = CS_MODE_ARM; }
  else if (target == "mips64el") { arch = CS_ARCH_MIPS; mode = CS_MODE_MIPS64R2; }
  else if (target == "ppc64el") { arch = CS_ARCH_PPC; mode = CS_MODE_64; }
  else if (target == "riscv64") { arch = CS_ARCH_RISCV; mode = cs_mode(CS_MODE_RISCV64 | CS_MODE_RISCV_C | CS_MODE_RISCV_A | CS_MODE_RISCV_FD); }
  else return 2;

  std::ifstream input(argv[2], std::ios::binary);
  std::vector<uint8_t> text(std::istreambuf_iterator<char>(input), {});
  csh handle = 0;
  if (!input || text.empty() || output > 5 || repeats == 0 ||
      cs_open(arch, mode, &handle) != CS_ERR_OK ||
      cs_option(handle, CS_OPT_DETAIL, output >= 2 ? CS_OPT_ON : CS_OPT_OFF) != CS_ERR_OK ||
      cs_option(handle, CS_OPT_TEXT, output ? CS_OPT_ON : CS_OPT_OFF) != CS_ERR_OK) return 3;
  if (output >= 3) {
    if (arch != CS_ARCH_RISCV) return 6;
    const unsigned detail = output == 4 ? CS_OPT_DETAIL_UNCOMPRESSED_REAL : CS_OPT_DETAIL_REAL;
    if (cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON | detail) != CS_ERR_OK) return 7;
    if (output == 4 && cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_REAL) != CS_ERR_OK) return 8;
    if (output == 5 && cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_UNCOMPRESSED_REAL) != CS_ERR_OK) return 9;
  }
  cs_insn *insn = cs_malloc(handle);
  if (!insn) return 4;
  uint64_t accepted = 0, rejected = 0, value = 0, boundaries = 14695981039346656037ull;
  const auto start = std::chrono::steady_clock::now();
  const auto cpu = std::clock();
  for (unsigned rep = 0; rep < repeats; ++rep) {
    const uint8_t *cursor = text.data();
    size_t left = text.size();
    uint64_t ip = 0x100000;
    while (left) {
      if (!cs_disasm_iter(handle, &cursor, &left, &ip, insn)) {
        const size_t step = std::min(left, size_t(arch == CS_ARCH_RISCV ? 2 : 4));
        left -= step;
        cursor += step;
        ip += step;
        ++rejected;
        boundaries = (boundaries ^ ip) * 1099511628211ull;
        continue;
      }
      ++accepted;
      boundaries = (boundaries ^ (ip + insn->size)) * 1099511628211ull;
      value += insn->id;
      if (output) value += std::strlen(insn->mnemonic) + std::strlen(insn->op_str);
      if (output >= 2) {
        cs_regs reads{}, writes{};
        uint8_t nr = 0, nw = 0;
        const cs_err err = cs_regs_access(handle, insn, reads, &nr, writes, &nw);
        if (err == CS_ERR_ARCH && arch == CS_ARCH_PPC) {
          for (unsigned i=0; i<insn->detail->regs_read_count; ++i) value += insn->detail->regs_read[i];
          for (unsigned i=0; i<insn->detail->regs_write_count; ++i) value += insn->detail->regs_write[i];
        } else if (err != CS_ERR_OK) return 5;
        for (unsigned i=0; i<nr; ++i) value += reads[i];
        for (unsigned i=0; i<nw; ++i) value += writes[i];
        value += insn->detail->groups_count;
      }
    }
  }
  const uint64_t cpu_ns = uint64_t(std::clock()-cpu) * 1000000000ull / CLOCKS_PER_SEC;
  const auto wall = std::chrono::duration_cast<std::chrono::nanoseconds>(
      std::chrono::steady_clock::now()-start).count();
  std::printf("%llu %lld %llu %llu %llu %llu\n",(unsigned long long)cpu_ns,(long long)wall,
              (unsigned long long)accepted,(unsigned long long)rejected,
              (unsigned long long)boundaries,(unsigned long long)value);
  cs_free(insn,1);
  cs_close(&handle);
}
