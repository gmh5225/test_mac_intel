#include <capstone/capstone.h>
#include <algorithm>
#include <array>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <fstream>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <unistd.h>
#include <vector>
#ifndef RTLD_FIRST
#define RTLD_FIRST 0
#endif

static uint64_t comparisons, rng = UINT64_C(0x91be8cd7c965a0f3);
static cs_insn *active_insn;
static unsigned callback_count;
static uint64_t callback_hash;
static void mix(const void *data, size_t size) {
  const auto *bytes = static_cast<const unsigned char *>(data);
  for (size_t i = 0; i < size; ++i)
    callback_hash = (callback_hash ^ bytes[i]) * UINT64_C(1099511628211);
}
static int custom_format(char *buffer, size_t size, const char *format, va_list args) {
  ++callback_count;
  mix(format, std::strlen(format));
  if (active_insn) {
    cs_insn snapshot = *active_insn;
    snapshot.detail = nullptr;
    mix(&snapshot, sizeof(snapshot));
    if (active_insn->detail) mix(active_insn->detail, sizeof(cs_detail));
  }
  int result = std::vsnprintf(buffer, size, format, args);
  mix(&result, sizeof(result));
  if (result >= 0 && size) mix(buffer, std::min(size - 1, size_t(result)));
  return result;
}
static uint64_t random_word() {
  rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng;
}

struct API {
  void *library;
  decltype(&::cs_open) open;
  decltype(&::cs_close) close;
  decltype(&::cs_option) option;
  decltype(&::cs_disasm_iter) iter;
  decltype(&::cs_errno) error;
  decltype(&::cs_regs_access) regs;
  using Counter = unsigned long long (*)();
  Counter checks, slots;
  explicit API(const char *path) {
    library = dlopen(path, RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!library) throw std::runtime_error(dlerror());
#define LOAD(field, name) field = reinterpret_cast<decltype(field)>(dlsym(library, name)); if (!field) throw std::runtime_error(name)
    LOAD(open, "cs_open"); LOAD(close, "cs_close"); LOAD(option, "cs_option");
    LOAD(iter, "cs_disasm_iter"); LOAD(error, "cs_errno"); LOAD(regs, "cs_regs_access");
#undef LOAD
    checks = reinterpret_cast<Counter>(dlsym(library, "a64_probe_probe_checks"));
    slots = reinterpret_cast<Counter>(dlsym(library, "a64_probe_probe_slots"));
  }
};

int main(int argc, char **argv) {
  try {
    if (argc < 4 || argc > 5) throw std::runtime_error("baseline candidate CORPUS [custom]");
    API api[2] = {API(argv[1]), API(argv[2])};
    if (api[0].iter == api[1].iter) throw std::runtime_error("libraries coalesced");
    const bool custom = argc == 5 && std::string(argv[4]) == "custom";
    if (custom) {
      cs_opt_mem memory = {std::malloc, std::calloc, std::realloc, std::free, custom_format};
      for (auto &a : api)
        if (a.option(0, CS_OPT_MEM, size_t(&memory)) != CS_ERR_OK)
          throw std::runtime_error("custom callbacks");
    }
    const size_t page = size_t(sysconf(_SC_PAGESIZE));
    void *region = mmap(nullptr, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (region == MAP_FAILED || mprotect(static_cast<uint8_t *>(region) + page, page, PROT_NONE))
      throw std::runtime_error("guard pages");
    std::vector<std::vector<uint8_t>> corpora;
    for (const char *name : {"ls", "cp", "sort", "mc"}) {
      std::string path = std::string(argv[3]) + "/arm64-" + std::string(name) + ".text";
      std::ifstream file(path, std::ios::binary);
      if (!file) throw std::runtime_error(path);
      corpora.emplace_back(std::istreambuf_iterator<char>(file), std::istreambuf_iterator<char>());
    }
    const unsigned modes[] = {0U, CS_MODE_APPLE_PROPRIETARY, CS_MODE_BIG_ENDIAN,
                              unsigned(CS_MODE_APPLE_PROPRIETARY) | unsigned(CS_MODE_BIG_ENDIAN)};
    const unsigned syntaxes[] = {CS_OPT_SYNTAX_DEFAULT, CS_OPT_SYNTAX_REAL, CS_OPT_SYNTAX_ALIAS,
                                 CS_OPT_SYNTAX_AARCH64_EXPLICIT_WIDE_IMM};
    const unsigned details[] = {CS_OPT_OFF, CS_OPT_ON, CS_OPT_ON | CS_OPT_DETAIL_REAL, CS_OPT_ON | CS_OPT_DETAIL_ALIAS};
    unsigned configurations = 0;
    for (unsigned features : modes) for (unsigned syntax : syntaxes) for (unsigned detail : details)
        for (unsigned text : {CS_OPT_OFF, CS_OPT_ON}) {
          const cs_mode mode = cs_mode(features);
          csh handles[2] = {};
          cs_err opened[2];
          for (unsigned side = 0; side < 2; ++side)
            opened[side] = api[side].open(CS_ARCH_AARCH64, mode, &handles[side]);
          if (opened[0] != opened[1]) throw std::runtime_error("mode admission differs");
          if (opened[0] != CS_ERR_OK) continue;
          for (unsigned side = 0; side < 2; ++side) {
            if (api[side].option(handles[side], CS_OPT_SYNTAX, syntax) != CS_ERR_OK ||
                api[side].option(handles[side], CS_OPT_DETAIL, detail) != CS_ERR_OK ||
                api[side].option(handles[side], CS_OPT_TEXT, text) != CS_ERR_OK)
              throw std::runtime_error("options");
          }
          auto compare = [&](const uint8_t *bytes, size_t length, uint64_t address) {
            cs_insn insn[2]; cs_detail state[2];
            bool ok[2]; cs_err errors[2];
            const uint8_t *cursor[2] = {bytes, bytes};
            size_t remaining[2] = {length, length};
            uint64_t next[2] = {address, address};
            unsigned callbacks[2]; uint64_t hashes[2];
            for (unsigned side = 0; side < 2; ++side) {
              std::memset(&insn[side], 0xa5, sizeof(cs_insn));
              std::memset(&state[side], 0xa5, sizeof(cs_detail));
              insn[side].detail = &state[side]; active_insn = &insn[side];
              callback_count = 0; callback_hash = UINT64_C(1469598103934665603);
              ok[side] = api[side].iter(handles[side], &cursor[side], &remaining[side], &next[side], &insn[side]);
              callbacks[side] = callback_count; hashes[side] = callback_hash;
              active_insn = nullptr; errors[side] = api[side].error(handles[side]);
              if (insn[side].detail != &state[side]) throw std::runtime_error("detail pointer restoration");
              insn[side].detail = nullptr;
            }
            bool bad = ok[0] != ok[1] || errors[0] != errors[1] || cursor[0] != cursor[1] ||
              remaining[0] != remaining[1] || next[0] != next[1] ||
              callbacks[0] != callbacks[1] || hashes[0] != hashes[1] ||
              std::memcmp(&insn[0], &insn[1], sizeof(cs_insn)) ||
              std::memcmp(&state[0], &state[1], sizeof(cs_detail));
            if (ok[0] && ok[1] && detail) {
              cs_regs reads[2] = {}, writes[2] = {};
              uint8_t nr[2] = {}, nw[2] = {};
              for (unsigned side = 0; side < 2; ++side) {
                insn[side].detail = &state[side];
                errors[side] = api[side].regs(handles[side], &insn[side], reads[side], &nr[side], writes[side], &nw[side]);
              }
              bad |= errors[0] != errors[1] || nr[0] != nr[1] || nw[0] != nw[1] ||
                std::memcmp(reads[0], reads[1], sizeof(cs_regs)) || std::memcmp(writes[0], writes[1], sizeof(cs_regs));
            }
            if (bad) {
              std::fprintf(stderr, "AArch64 differs mode=%x syntax=%u detail=%u text=%u length=%zu address=%llx count=%llu bytes=",
                features, syntax, detail, text, length, (unsigned long long)address, (unsigned long long)comparisons);
              for (size_t i = 0; i < std::min(length, size_t(16)); ++i) std::fprintf(stderr, "%02x", bytes[i]);
              std::fprintf(stderr, "\n"); throw std::runtime_error("public state/callback mismatch");
            }
            ++comparisons;
            return ok[0] ? size_t(cursor[0] - bytes) : size_t(1);
          };
          uint8_t *tail = static_cast<uint8_t *>(region) + page;
          // Cover every high halfword, each with a reproducible low-half sample.
          for (unsigned high = 0; high <= 0xffff; ++high) {
            const uint32_t word=(uint32_t(high) << 16) | (random_word() & 0xffff);
            std::memcpy(tail-4,&word,sizeof(word));
            compare(tail-4,4,0x100000 + high*4);
          }
          for (unsigned seed = 0; seed < 4; ++seed) for (size_t length = 0; length <= 16; ++length) {
            for (size_t i = 0; i < length; ++i) (tail - length)[i] = uint8_t(random_word());
            compare(tail - length, length, UINT64_MAX - seed);
          }
          std::array<uint8_t, 16> random;
          for (unsigned i = 0; i < 2048; ++i) {
            for (auto &byte : random) byte = uint8_t(random_word());
            compare(random.data(), random.size(), (i & 1) ? UINT64_MAX - i : i * 4);
          }
          for (const auto &bytes : corpora)
            for (size_t pos = 0; pos + 4 <= bytes.size(); pos += 4)
              compare(bytes.data()+pos,4,0x100000+pos);
          for (unsigned side = 0; side < 2; ++side) api[side].close(&handles[side]);
          ++configurations;
          std::printf("{\"mode\":%u,\"syntax\":%u,\"detail\":%u,\"text\":%u,\"comparisons\":%llu}\n",
            features, syntax, detail, text, (unsigned long long)comparisons);
          std::fflush(stdout);
        }
    munmap(region, page * 2);
    auto reads = api[1].checks ? api[1].checks() : 0;
    auto slots = api[1].slots ? api[1].slots() : 0;
    if (api[1].checks && (!reads || !slots)) throw std::runtime_error("probe did not observe outer instruction reads");
    std::printf("{\"configurations\":%u,\"comparisons\":%llu,\"custom\":%s,\"outer_reads_checked\":%llu,\"slot_mask\":%llu}\n",
      configurations, (unsigned long long)comparisons, custom ? "true" : "false", reads, slots);
  } catch (const std::exception &error) {
    std::fprintf(stderr, "%s\n", error.what()); return 1;
  }
}
