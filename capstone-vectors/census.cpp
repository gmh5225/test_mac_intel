#include <capstone/capstone.h>
#include <dlfcn.h>
#include <array>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <map>
#include <stdexcept>
#include <string>
#include <tuple>
#include <vector>

struct API {
  void *library;
  decltype(&cs_open) open;
  decltype(&cs_close) close;
  decltype(&cs_option) option;
  decltype(&cs_malloc) alloc;
  decltype(&cs_free) free;
  decltype(&cs_disasm_iter) iter;
  using Hit = bool (*)(csh, const uint8_t *, size_t, cs_insn *);
  Hit hit;
  explicit API(const char *name) {
    library = dlopen(name, RTLD_NOW | RTLD_LOCAL);
    if (!library) throw std::runtime_error(dlerror());
#define LOAD(field, symbol) field = reinterpret_cast<decltype(field)>(dlsym(library, symbol))
    LOAD(open, "cs_open"); LOAD(close, "cs_close"); LOAD(option, "cs_option");
    LOAD(alloc, "cs_malloc"); LOAD(free, "cs_free"); LOAD(iter, "cs_disasm_iter");
    LOAD(hit, "cs_test_owned_hit");
#undef LOAD
    if (!open || !close || !option || !alloc || !free || !iter || !hit)
      throw std::runtime_error("missing observer entry");
  }
};

struct Machine {
  API api;
  csh handle = 0;
  cs_insn *insn;
  Machine(const char *name, unsigned bits, bool detail = false) : api(name) {
    if (api.open(CS_ARCH_X86, bits == 64 ? CS_MODE_64 : CS_MODE_32, &handle) ||
        api.option(handle, CS_OPT_TEXT, CS_OPT_ON) ||
        api.option(handle, CS_OPT_DETAIL, detail ? CS_OPT_ON : CS_OPT_OFF))
      throw std::runtime_error("observer options");
    insn = api.alloc(handle);
    if (!insn) throw std::runtime_error("observer allocation");
  }
  ~Machine() { api.free(insn, 1); api.close(&handle); }
};

struct Stat { uint64_t count = 0; std::string sample; };
using Key = std::tuple<std::string, std::string, unsigned, unsigned, unsigned,
                       unsigned, unsigned, unsigned, unsigned, unsigned>;

int main(int argc, char **argv) {
  if (argc != 6) return 1;
  const unsigned bits = std::stoul(argv[3]);
  Machine base(argv[1], bits, true), candidate(argv[2], bits);
  if (base.api.hit == candidate.api.hit) return 2;
  std::ifstream input(argv[4], std::ios::binary), spans(argv[5]);
  if (!input || !spans) return 3;
  const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input), {}};
  std::map<Key, Stat> histogram;
  uint64_t decoded = 0, invalid = 0, old_hits = 0, new_hits = 0, misses = 0;
  size_t start, left;
  uint64_t address;
  while (spans >> start >> left >> address) {
    if (start > bytes.size() || left > bytes.size() - start) return 4;
    const uint8_t *cursor = bytes.data() + start;
    while (left) {
      const uint8_t *begin = cursor;
      const size_t available = left;
      if (!base.api.iter(base.handle, &cursor, &left, &address, base.insn)) {
        ++invalid; ++cursor; --left; ++address; continue;
      }
      ++decoded;
      cs_insn old{}, now{};
      const bool had = base.api.hit(base.handle, begin, available, &old);
      const bool has = candidate.api.hit(candidate.handle, begin, available, &now);
      if ((had && (!has || old.id != now.id || old.size != now.size)) ||
          (has && (now.id != base.insn->id || now.size != base.insn->size)))
        throw std::runtime_error("admission or canonical identity mismatch");
      std::string route = had ? "existing" : has ? "new" : "miss";
      if (had) ++old_hits; else if (has) ++new_hits; else ++misses;
      unsigned prefix = 0, map = 0, opcode = begin[0], w = 0, ll = 0, pp = 0;
      unsigned mod = 4, memory = 0, evex_flags = 0;
      const auto size = base.insn->size;
      if (begin[0] == 0x62 && size >= 6 && base.insn->id != X86_INS_BOUND) {
        prefix = 4; map = begin[1] & 15; opcode = begin[4];
        w = begin[2] >> 7; ll = (begin[3] >> 5) & 3; pp = begin[2] & 3;
        evex_flags = begin[3] & 0x97;
      } else if (begin[0] == 0xc4 && size >= 5 && base.insn->id != X86_INS_LES) {
        prefix = 3; map = begin[1] & 31; opcode = begin[3];
        w = begin[2] >> 7; ll = (begin[2] >> 2) & 1; pp = begin[2] & 3;
      } else if (begin[0] == 0xc5 && size >= 4 && base.insn->id != X86_INS_LDS) {
        prefix = 2; map = 1; opcode = begin[2];
        ll = (begin[1] >> 2) & 1; pp = begin[1] & 3;
      }
      if (!base.insn->detail) throw std::runtime_error("missing canonical detail");
      const cs_x86 &x = base.insn->detail->x86;
      if (!prefix) {
        opcode = x.opcode[0];
        if (opcode == 0x0f) {
          map = 1; opcode = x.opcode[1];
          if (opcode == 0x38 || opcode == 0x3a) {
            map = opcode == 0x38 ? 2 : 3; opcode = x.opcode[2];
          }
        }
        w = (x.rex >> 3) & 1;
        for (unsigned i = 0; i < size; ++i) {
          const unsigned b = begin[i];
          if (b == 0x66) pp = 1;
          else if (b == 0xf3) pp = 2;
          else if (b == 0xf2) pp = 3;
          else if (b == 0x67 || b == 0xf0 || b == 0x26 || b == 0x2e ||
                   b == 0x36 || b == 0x3e || b == 0x64 || b == 0x65 ||
                   (bits == 64 && (b & 0xf0) == 0x40)) continue;
          else break;
        }
      }
      if (x.encoding.modrm_offset) mod = x.modrm >> 6;
      for (unsigned i = 0; i < x.op_count; ++i) {
        if (x.operands[i].type != X86_OP_MEM) continue;
        const x86_op_mem &m = x.operands[i].mem;
        if (m.index != X86_REG_INVALID) memory = 2;
        else if (m.base == X86_REG_RIP || m.base == X86_REG_EIP || m.base == X86_REG_IP) memory = 3;
        else if (m.base == X86_REG_INVALID) memory = 4;
        else memory = 1;
        break;
      }
      const unsigned family = prefix ? (prefix << 8) | map : 0x10000 | map;
      Key key{route, base.insn->mnemonic, family, opcode, w, ll, pp, mod, memory, evex_flags};
      auto &stat = histogram[key];
      if (!stat.count) {
        constexpr char hex[] = "0123456789abcdef";
        for (unsigned i = 0; i < size; ++i) {
          stat.sample += hex[begin[i] >> 4]; stat.sample += hex[begin[i] & 15];
        }
      }
      ++stat.count;
    }
  }
  if (decoded != old_hits + new_hits + misses) return 5;
  std::cout << "{\"decoded\":" << decoded << ",\"invalid_bytes\":" << invalid
            << ",\"existing\":" << old_hits << ",\"new\":" << new_hits
            << ",\"miss\":" << misses << ",\"rows\":[";
  bool comma = false;
  for (const auto &[key, stat] : histogram) {
    const auto &[route, mnemonic, family, opcode, w, ll, pp, mod, memory, flags] = key;
    if (comma) std::cout << ',';
    comma = true;
    std::cout << "{\"route\":" << std::quoted(route) << ",\"mnemonic\":" << std::quoted(mnemonic)
              << ",\"family\":" << family << ",\"opcode\":" << opcode << ",\"w\":" << w
              << ",\"ll\":" << ll << ",\"pp\":" << pp << ",\"mod\":" << mod
              << ",\"memory\":" << memory << ",\"evex_flags\":" << flags
              << ",\"count\":" << stat.count << ",\"sample\":" << std::quoted(stat.sample) << '}';
  }
  std::cout << "]}\n";
}
