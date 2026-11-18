#include <capstone/capstone.h>
#include <dlfcn.h>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <vector>

struct API {
  void *library;
  csh handle = 0;
  decltype(&cs_open) open;
  decltype(&cs_close) close;
  decltype(&cs_option) option;
  decltype(&cs_disasm_iter) iter;
  decltype(&cs_errno) error;
  bool (*hit)(csh, const uint8_t *, size_t, cs_insn *);
  API(const char *path, unsigned bits) {
    library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library) throw std::runtime_error(dlerror());
#define LOAD(member, symbol) member = reinterpret_cast<decltype(member)>(dlsym(library, symbol)); if (!member) throw std::runtime_error(symbol)
    LOAD(open, "cs_open"); LOAD(close, "cs_close"); LOAD(option, "cs_option");
    LOAD(iter, "cs_test_owned_iter"); LOAD(error, "cs_errno"); LOAD(hit, "cs_test_owned_hit");
#undef LOAD
    if (open(CS_ARCH_X86, bits == 32 ? CS_MODE_32 : CS_MODE_64, &handle) ||
        option(handle, CS_OPT_DETAIL, CS_OPT_ON) || option(handle, CS_OPT_TEXT, CS_OPT_ON))
      throw std::runtime_error("open/options");
  }
  ~API() { close(&handle); dlclose(library); }
};

struct Count { uint64_t count = 0; std::string bytes; };
using Counts = std::map<std::string, Count>;

int main(int argc, char **argv) {
  if (argc != 6) return 1;
  unsigned bits = std::stoul(argv[5]);
  API base(argv[1], bits), candidate(argv[2], bits);
  std::ifstream binary(argv[3], std::ios::binary), spans(argv[4]);
  if (!binary || !spans) throw std::runtime_error("input files");
  std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(binary)), {});
  uint64_t offset, size, address, accepted = 0, excluded = 0, compared = 0;
  Counts total;
  while (spans >> offset >> size >> address) {
    if (offset > bytes.size() || size > bytes.size() - offset) throw std::runtime_error("span extent");
    Counts local;
    uint64_t pos = 0;
    while (pos < size) {
      cs_insn insns[2]{};
      cs_detail details[2]{};
      bool ok[2], fast[2];
      cs_err errors[2];
      uint64_t ip[2] = {address + pos, address + pos};
      size_t left[2] = {size_t(size - pos), size_t(size - pos)};
      const uint8_t *code = bytes.data() + offset + pos;
      const uint8_t *cursor[2] = {code, code};
      API *apis[] = {&base, &candidate};
      for (unsigned i = 0; i < 2; ++i) {
        cs_insn probe{}; cs_detail extra{};
        probe.address = ip[i]; probe.detail = &extra;
        fast[i] = apis[i]->hit(apis[i]->handle, code, left[i], &probe);
        insns[i].detail = &details[i];
        ok[i] = apis[i]->iter(apis[i]->handle, &cursor[i], &left[i], &ip[i], &insns[i]);
        errors[i] = apis[i]->error(apis[i]->handle);
        insns[i].detail = nullptr;
      }
      if (ok[0] != ok[1] || errors[0] != errors[1] || left[0] != left[1] || ip[0] != ip[1] ||
          cursor[0] != cursor[1] || std::memcmp(insns, insns + 1, sizeof(cs_insn)) ||
          std::memcmp(details, details + 1, sizeof(cs_detail)))
        throw std::runtime_error("complete real-input record mismatch");
      ++compared;
      if (fast[0] && !fast[1]) throw std::runtime_error("existing output admission lost");
      if (!ok[0]) break;
      if (!insns[0].size || insns[0].size > size - pos) throw std::runtime_error("decoded extent");
      bool memory = false;
      for (unsigned i = 0; i < details[0].x86.op_count; ++i)
        memory |= details[0].x86.operands[i].type == X86_OP_MEM;
      std::string kind = code[0] == 0xc5 ? "c5" : code[0] == 0xc4 ? "c4" : code[0] == 0x62 ? "62" : "other";
      const auto &x = details[0].x86;
      std::string address_form = !memory ? "none" :
        kind == "c4" || kind == "c5" ?
          (x.modrm & 7) == 4 ? "sib" : (x.modrm & 0xc7) == 5 ? "no-base" : "base" : "other";
      std::string key = std::string(fast[0] ? "original" : fast[1] ? "added" : "fallback") + '\t' +
                        kind + '\t' + (memory ? "memory" : "nonmemory") + '\t' + address_form + '\t' + insns[0].mnemonic;
      auto &row = local[key];
      ++row.count;
      if (row.bytes.empty()) {
        char hex[3];
        for (unsigned i = 0; i < insns[0].size; ++i) {
          std::snprintf(hex, sizeof(hex), "%02x", code[i]); row.bytes += hex;
        }
      }
      pos += insns[0].size;
    }
    if (pos != size) { ++excluded; continue; }
    ++accepted;
    for (const auto &[key, count] : local) {
      auto &row = total[key]; row.count += count.count;
      if (row.bytes.empty()) row.bytes = count.bytes;
    }
  }
  std::printf("summary\t%llu\t%llu\t%llu\n", (unsigned long long)accepted,
              (unsigned long long)excluded, (unsigned long long)compared);
  for (const auto &[key, row] : total)
    std::printf("row\t%s\t%llu\t%s\n", key.c_str(), (unsigned long long)row.count, row.bytes.c_str());
}
