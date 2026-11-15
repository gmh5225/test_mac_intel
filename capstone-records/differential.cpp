#include <capstone/capstone.h>
#define GET_INSTRINFO_ENUM
#include "arch/X86/X86GenInstrInfo.inc"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <vector>

struct API {
  void *library;
  decltype(&cs_open) open;
  decltype(&cs_close) close;
  decltype(&cs_option) option;
  decltype(&cs_disasm_iter) iter;
  decltype(&cs_errno) error;
  decltype(&cs_regs_access) access;
  void (*map)(csh, cs_insn *, unsigned);
  explicit API(const char *path, bool mapping = true) {
    library = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!library) throw std::runtime_error(dlerror());
#define LOAD(field, name) field = reinterpret_cast<decltype(field)>(dlsym(library, name)); if (!field) throw std::runtime_error(name)
    LOAD(open, "cs_open"); LOAD(close, "cs_close");
    LOAD(option, "cs_option"); LOAD(iter, "cs_disasm_iter");
    LOAD(error, "cs_errno"); LOAD(access, "cs_regs_access");
    map = nullptr;
    if (mapping) { LOAD(map, "cs_test_map"); }
#undef LOAD
  }
};
struct Machine {
  API &api;
  csh handle = 0;
  cs_mode mode;
  Machine(API &api, cs_mode mode, unsigned flags, unsigned syntax)
      : api(api), mode(mode) {
    if (api.open(CS_ARCH_X86, mode, &handle) ||
        api.option(handle, CS_OPT_DETAIL, flags & 2 ? CS_OPT_ON : CS_OPT_OFF) ||
        api.option(handle, CS_OPT_TEXT, flags & 1 ? CS_OPT_ON : CS_OPT_OFF) ||
        api.option(handle, CS_OPT_SKIPDATA, flags & 4 ? CS_OPT_ON : CS_OPT_OFF) ||
        api.option(handle, CS_OPT_SYNTAX, syntax ? CS_OPT_SYNTAX_ATT : CS_OPT_SYNTAX_INTEL))
      throw std::runtime_error("open/options");
  }
  ~Machine() { api.close(&handle); }
};
static uint64_t records = 0, mappings = 0, corrected = 0, mapping_corrections = 0;
static uint32_t state = 0xa475ff39;
static uint32_t random_word() {
  state ^= state << 13; state ^= state >> 17; state ^= state << 5; return state;
}
static void remove_ds(cs_detail &detail) {
  if (detail.regs_read_count != 1 || detail.regs_read[0] != X86_REG_DS)
    throw std::runtime_error("unexpected original implicit registers");
  detail.regs_read_count = 0;
  detail.regs_read[0] = 0;
}
static bool scalar_internal(unsigned id) {
  switch (id) {
  case X86_MOVSDmr: case X86_MOVSDrm: case X86_MOVSDrr: case X86_MOVSDrr_REV:
  case X86_CMPSDrm: case X86_CMPSDrm_Int: case X86_CMPSDrm_alt:
  case X86_CMPSDrr: case X86_CMPSDrr_Int: case X86_CMPSDrr_alt:
    return true;
  default: return false;
  }
}
static void compare_mapping(Machine &a, Machine &b, unsigned id,
                            bool detail, unsigned address_size) {
  cs_insn insns[2]{};
  cs_detail details[2]{};
  Machine *sides[] = {&a, &b};
  for (unsigned side = 0; side != 2; ++side) {
    details[side].x86.addr_size = address_size;
    insns[side].detail = detail ? &details[side] : nullptr;
    sides[side]->api.map(sides[side]->handle, &insns[side], id);
    insns[side].detail = nullptr;
  }
  if (detail && a.mode != CS_MODE_64 && scalar_internal(id)) {
    remove_ds(details[0]); ++mapping_corrections;
  }
  if (std::memcmp(insns, insns + 1, sizeof(cs_insn)) ||
      std::memcmp(details, details + 1, sizeof(cs_detail))) {
    std::fprintf(stderr, "mapping mismatch id=%u mode=%u address-size=%u detail=%u\n",
                 id, a.mode, address_size, detail); std::exit(3);
  }
  ++mappings;
}
static size_t compare(Machine &a, Machine &b, const uint8_t *code, size_t length,
                    bool detail) {
  cs_insn insns[2]; cs_detail details[2]; bool success[2]; cs_err errors[2];
  uint64_t pc = (uint64_t(state) << 32) | ~state, ips[] = {pc, pc};
  size_t sizes[] = {length, length}; const uint8_t *cursors[] = {code, code};
  Machine *sides[] = {&a, &b};
  for (unsigned side = 0; side != 2; ++side) {
    std::memset(&insns[side], state, sizeof(cs_insn));
    std::memset(&details[side], state, sizeof(cs_detail));
    insns[side].illegal = insns[side].is_alias = insns[side].usesAliasDetails = false;
    insns[side].detail = detail ? &details[side] : nullptr;
    auto &m = *sides[side];
    success[side] = m.api.iter(m.handle, &cursors[side], &sizes[side], &ips[side], &insns[side]);
    errors[side] = m.api.error(m.handle);
  }
  if (success[0] && detail && insns[0].id && a.mode != CS_MODE_64 &&
      (insns[0].id == X86_INS_MOVSD || insns[0].id == X86_INS_CMPSD) &&
      details[0].x86.opcode[0] == 0x0f &&
      (details[0].x86.opcode[1] == 0x10 || details[0].x86.opcode[1] == 0x11 ||
       details[0].x86.opcode[1] == 0xc2)) {
    remove_ds(details[0]); ++corrected;
  }
  bool registers_equal = true;
  if (success[0] && success[1] && detail && insns[0].id && insns[1].id) {
    cs_regs reads[2]{}, writes[2]{}; uint8_t nr[2]{}, nw[2]{}; cs_err access[2];
    for (unsigned side = 0; side != 2; ++side)
      access[side] = sides[side]->api.access(sides[side]->handle, &insns[side],
                         reads[side], &nr[side], writes[side], &nw[side]);
    registers_equal = access[0] == access[1] && nr[0] == nr[1] && nw[0] == nw[1] &&
                      !std::memcmp(reads, reads + 1, sizeof(cs_regs)) &&
                      !std::memcmp(writes, writes + 1, sizeof(cs_regs));
  }
  for (unsigned side = 0; side != 2; ++side) {
    if (insns[side].detail != (detail ? &details[side] : nullptr))
      throw std::runtime_error("detail pointer");
    insns[side].detail = nullptr;
  }
  if (success[0] != success[1] || errors[0] != errors[1] || ips[0] != ips[1] ||
      sizes[0] != sizes[1] || cursors[0] != cursors[1] || !registers_equal ||
      std::memcmp(insns, insns + 1, sizeof(cs_insn)) ||
      (detail && std::memcmp(details, details + 1, sizeof(cs_detail)))) {
    std::fprintf(stderr, "record mismatch after %llu mode=%u bytes=", (unsigned long long)records, a.mode);
    for (unsigned i = 0; i < length; ++i) std::fprintf(stderr, "%02x", code[i]);
    std::fprintf(stderr, " ids=%u,%u implicit=%u,%u\n", insns[0].id, insns[1].id,
                 details[0].regs_read_count, details[1].regs_read_count); std::exit(4);
  }
  ++records;
  return success[0] ? length - sizes[0] : 1;
}
int main(int argc, char **argv) {
  if (argc != 3 && argc != 5) return 1;
  const bool file_mode = argc == 5;
  API a(argv[1], !file_mode), b(argv[2], !file_mode);
  if ((!file_mode && a.map == b.map) || a.iter == b.iter) return 2;
  if (file_mode) {
    const unsigned bits = std::stoul(argv[3]);
    if (bits != 16 && bits != 32 && bits != 64) return 6;
    std::ifstream file(argv[4], std::ios::binary);
    if (!file) throw std::runtime_error("input file");
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), {});
    for (unsigned flags : {0u, 1u, 3u}) {
      Machine x(a, bits == 16 ? CS_MODE_16 : bits == 32 ? CS_MODE_32 : CS_MODE_64, flags, 0);
      Machine y(b, x.mode, flags, 0);
      for (size_t offset = 0; offset < bytes.size();) {
        const size_t consumed = compare(x, y, bytes.data() + offset, bytes.size() - offset, flags & 2);
        if (!consumed) throw std::runtime_error("zero instruction length");
        offset += consumed;
      }
    }
    std::printf("{\"records\":%llu,\"scalar_ds_corrections\":%llu,\"bytes\":%zu,\"bits\":%u,\"other_bytes_cursor_errors_accesses_equal\":true}\n",
      (unsigned long long)records, (unsigned long long)corrected, bytes.size(), bits);
    return 0;
  }
  for (cs_mode mode : {CS_MODE_16, CS_MODE_32, CS_MODE_64})
    for (unsigned flags : {1u, 3u}) {
      Machine x(a, mode, flags, 0), y(b, mode, flags, 0);
      for (unsigned address_size : {2u, 4u, 8u})
        for (unsigned id = 0; id < X86_INSTRUCTION_LIST_END; ++id)
          compare_mapping(x, y, id, flags & 2, address_size);
    }
  const uint8_t prefixes[][3] = {{0}, {0x66}, {0x67}, {0x2e}, {0x3e}, {0x64},
    {0x65}, {0xf0}, {0xf2}, {0xf3}, {0x66,0xf3}, {0x67,0xf0}, {0xf3,0xf2},
    {0x66,0xf2}, {0x2e,0x3e}, {0x64,0x67}};
  for (cs_mode mode : {CS_MODE_16, CS_MODE_32, CS_MODE_64})
    for (unsigned flags = 0; flags != 8; ++flags)
      for (unsigned syntax = 0; syntax != 2; ++syntax) {
        Machine x(a, mode, flags, syntax), y(b, mode, flags, syntax);
        const bool detail = flags & 2; uint8_t bytes[15];
        for (auto &prefix : prefixes)
          for (unsigned rex = 0; rex <= (mode == CS_MODE_64 ? 16u : 0u); ++rex)
            for (uint8_t opcode : {0x10, 0x11, 0xc2})
              for (unsigned modrm = 0; modrm != 256; ++modrm) {
                for (auto &v : bytes) v = random_word();
                unsigned n = 0;
                for (auto v : prefix) if (v) bytes[n++] = v;
                bytes[n++] = 0xf2;
                if (rex) bytes[n++] = 0x3f + rex;
                bytes[n++] = 0x0f; bytes[n++] = opcode; bytes[n++] = modrm;
                compare(x, y, bytes, sizeof(bytes), detail);
                compare(x, y, bytes, random_word() % 16, detail);
              }
        for (unsigned i = 0; i != 65536; ++i) {
          for (auto &v : bytes) v = random_word();
          bytes[0] = i; bytes[1] = i >> 8;
          compare(x, y, bytes, sizeof(bytes), detail);
          compare(x, y, bytes, i % 16, detail);
        }
      }
  if (mapping_corrections != 60 || !corrected) return 5;
  std::printf("{\"mappings\":%llu,\"mapping_corrections\":%llu,\"records\":%llu,\"scalar_ds_corrections\":%llu,\"other_bytes_cursor_errors_accesses_equal\":true}\n",
     (unsigned long long)mappings, (unsigned long long)mapping_corrections,
     (unsigned long long)records, (unsigned long long)corrected);
}
