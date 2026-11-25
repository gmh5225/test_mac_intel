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
  if (argc != 6) return 1;
  const std::string target = argv[1];
  const unsigned output = std::stoul(argv[3]), repeats = std::stoul(argv[4]);
  cs_arch arch;
  cs_mode mode;
  if (target == "arm64") { arch = CS_ARCH_AARCH64; mode = CS_MODE_LITTLE_ENDIAN; }
  else if (target == "arm") { arch = CS_ARCH_ARM; mode = CS_MODE_ARM; }
  else if (target == "mips64el") { arch = CS_ARCH_MIPS; mode = CS_MODE_MIPS64R2; }
  else if (target == "ppc64el") { arch = CS_ARCH_PPC; mode = CS_MODE_64; }
  else if (target == "riscv64") { arch = CS_ARCH_RISCV; mode = cs_mode(CS_MODE_RISCV64 | CS_MODE_RISCV_C | CS_MODE_RISCV_A); }
  else return 2;

  std::ifstream input(argv[2], std::ios::binary);
  std::vector<uint8_t> text(std::istreambuf_iterator<char>(input), {});
  struct Extent { size_t offset, length; uint64_t address; };
  std::ifstream range_file(argv[5]);
  std::vector<Extent> spans;
  Extent row{};
  while (range_file >> row.offset >> row.length >> row.address) {
    if (!row.length || row.length % 4 || row.offset > text.size() || row.length > text.size()-row.offset) return 4;
    spans.push_back(row);
  }
  if (!range_file.eof() || spans.empty() || arch != CS_ARCH_ARM) return 4;
  csh handle = 0;
  if (!input || text.empty() || output > 2 || repeats == 0 ||
      cs_open(arch, mode, &handle) != CS_ERR_OK ||
      cs_option(handle, CS_OPT_DETAIL, output == 2 ? CS_OPT_ON : CS_OPT_OFF) != CS_ERR_OK ||
      cs_option(handle, CS_OPT_TEXT, output ? CS_OPT_ON : CS_OPT_OFF) != CS_ERR_OK) return 3;
  cs_insn *insn = cs_malloc(handle);
  if (!insn) return 4;
  uint64_t accepted = 0, rejected = 0, value = 0, boundaries = 14695981039346656037ull;
  const auto start = std::chrono::steady_clock::now();
  const auto cpu = std::clock();
  for (unsigned rep = 0; rep < repeats; ++rep) {
   for (const Extent &span : spans) {
    const uint8_t *cursor = text.data()+span.offset;
    size_t left = span.length;
    uint64_t ip = span.address;
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
      if (output == 2) {
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
