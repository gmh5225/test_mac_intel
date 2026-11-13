#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dlfcn.h>
#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>
#include <capstone/capstone.h>
struct Library {
  void *image;
  std::string path;
  decltype(&cs_open) open;
  decltype(&cs_option) option;
  decltype(&cs_close) close;
  template<class T> T load(const char *name) {
    auto symbol=dlsym(image,name); Dl_info info{};
    if(!symbol || !dladdr(symbol,&info) || std::filesystem::canonical(info.dli_fname)!=std::filesystem::canonical(path))
      throw std::runtime_error(std::string("symbol/image: ")+name);
    return reinterpret_cast<T>(symbol);
  }
  explicit Library(const char *p):path(p) {
    image=dlopen(p,RTLD_NOW|RTLD_LOCAL);if(!image)throw std::runtime_error(dlerror());
    open=load<decltype(open)>("cs_open");option=load<decltype(option)>("cs_option");close=load<decltype(close)>("cs_close");
  }
  ~Library(){dlclose(image);}
};

#include <algorithm>
int main(int argc, char **argv) {
  try {
    if (argc != 4) throw std::runtime_error("baseline candidate quick|full");
    const bool full = std::string(argv[3]) == "full";
    if (!full && std::string(argv[3]) != "quick") throw std::runtime_error("profile");
    Library a(argv[1]), b(argv[2]);
    auto ia = a.load<decltype(&cs_disasm_iter)>("cs_disasm_iter");
    auto ib = b.load<decltype(&cs_disasm_iter)>("cs_disasm_iter");
    auto ea = a.load<decltype(&cs_errno)>("cs_errno");
    auto eb = b.load<decltype(&cs_errno)>("cs_errno");
    uint64_t checked = 0, successes = 0;
    std::vector<std::pair<std::string, uint64_t>> sections;
    auto run = [&](cs_mode mode, bool exhaustive) {
      csh ha = 0, hb = 0;
      if (a.open(CS_ARCH_X86, mode, &ha) || b.open(CS_ARCH_X86, mode, &hb) ||
          a.option(ha, CS_OPT_TEXT, CS_OPT_OFF) || b.option(hb, CS_OPT_TEXT, CS_OPT_OFF))
        throw std::runtime_error("handle setup");
      auto check = [&](const std::array<uint8_t, 16> &bytes, size_t n) {
        cs_insn x, y;
        std::memset(&x, 0xa5, sizeof(x));
        std::memset(&y, 0xa5, sizeof(y));
        x.detail = y.detail = nullptr;
        const uint8_t *pa = bytes.data(), *pb = bytes.data();
        size_t na = n, nb = n;
        uint64_t aa = 0xfffffffffffffff9ULL, ab = aa;
        bool ra = ia(ha, &pa, &na, &aa, &x), rb = ib(hb, &pb, &nb, &ab, &y);
        if (ra != rb || pa != pb || na != nb || aa != ab ||
            ea(ha) != eb(hb) || std::memcmp(&x, &y, sizeof(x))) {
          std::fprintf(stderr, "mismatch mode=%u n=%zu case=%llu ok=%d/%d id=%u/%u size=%u/%u bytes=",
                       unsigned(mode), n, (unsigned long long)checked, ra, rb, x.id, y.id, x.size, y.size);
          for (size_t i = 0; i < n; ++i) std::fprintf(stderr, "%02x", bytes[i]);
          std::fputc('\n', stderr);
          throw std::runtime_error("VEX public outcome differs");
        }
        ++checked;
        successes += ra;
      };
      std::array<uint8_t, 16> bytes{};
      for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = uint8_t(0x81 + 29 * i);
      uint64_t start = checked;
      if (exhaustive) {
        // All C4 first payloads include invalid maps, all R/X/B bits, and LDS ambiguity.
        for (unsigned p0 = 0; p0 < 256; ++p0)
          for (unsigned p1 = 0; p1 < 256; p1 += full ? 1 : 17)
            for (unsigned op = 0; op < 256; ++op)
              for (auto mr : {0x00, 0x0d, 0x54, 0x9c, 0xe0, 0xe9, 0xf2, 0xff}) {
                bytes[0] = 0xc4; bytes[1] = uint8_t(p0); bytes[2] = uint8_t(p1);
                bytes[3] = uint8_t(op); bytes[4] = uint8_t(mr);
                check(bytes, bytes.size());
              }
        uint64_t expected = uint64_t(256) * (full ? 256 : 16) * 256 * 8;
        if (checked - start != expected) throw std::runtime_error("C4 count");
        sections.emplace_back("c4-payload-opcode-forms", checked - start);
        start = checked;
        // All C5 payloads/opcodes and all ModRM group, address and register selections.
        for (unsigned p1 = 0; p1 < 256; ++p1)
          for (unsigned op = 0; op < 256; ++op)
            for (unsigned mr = 0; mr < 256; mr += full ? 1 : 17) {
              bytes[0] = 0xc5; bytes[1] = uint8_t(p1); bytes[2] = uint8_t(op); bytes[3] = uint8_t(mr);
              check(bytes, bytes.size());
            }
        expected = uint64_t(256) * 256 * (full ? 256 : 16);
        if (checked - start != expected) throw std::runtime_error("C5 count");
        sections.emplace_back("c5-payload-opcode-modrm", checked - start);
        start = checked;
        // Every /reg group and SIB byte, all valid maps, W/L/pp and register-vs-memory forms.
        for (unsigned map = 1; map <= 3; ++map)
          for (unsigned p = 0; p < 16; ++p)
            for (unsigned op = 0; op < 256; ++op)
              for (unsigned mr = 0; mr < 256; ++mr) {
                bytes[0] = 0xc4; bytes[1] = uint8_t(0xe0 | map);
                bytes[2] = uint8_t(0x78 | (p & 7) | ((p & 8) << 4));
                bytes[3] = uint8_t(op); bytes[4] = uint8_t(mr); bytes[5] = uint8_t(mr);
                check(bytes, bytes.size());
              }
        if (checked - start != uint64_t(3) * 16 * 256 * 256) throw std::runtime_error("groups count");
        sections.emplace_back("c4-map-groups", checked - start);
      }
      // Prefix, map, VVVV, immediates, every truncation, SIB and mode-priority regressions.
      const std::vector<std::vector<uint8_t>> seeds = {
        {0xc5,0xf8,0x77}, {0xc5,0xf0,0x77}, {0xc4,0xe1,0x74,0x58,0xc2},
        {0xc4,0xc1,0x74,0x58,0x55,0x20}, {0xc5,0xfa,0x10,0x44,0x24,0x80},
        {0xc4,0xe3,0x79,0x0f,0xc1,0xff}, {0xc4,0xe2,0x69,0x92,0x04,0x88},
        {0xc4,0xe2,0xfb,0xf7,0x44,0x24,0x80}, {0xc4,0xe3,0x79,0x4a,0xc0,0xf0},
        {0xc5,0xf8,0xc2,0xc1,0xff}, {0xc4,0xe1,0x79,0x85,0x80},
        {0xc4,0xe1,0x79,0xae,0x44,0x24,0x80}, {0xc4,0xe2,0x79,0xf8,0xc0},
        {0x66,0xc5,0xf8,0x77}, {0xf3,0xc5,0xf8,0x77}, {0x67,0xc4,0xe1,0x74,0x58,0x04,0x25,0,0,0,0},
        {0x48,0xc5,0xf8,0x77}, {0xc4,0x00}, {0xc5,0x00}
      };
      start = checked;
      for (const auto &seed : seeds) {
        for (size_t at = 0; at <= seed.size(); ++at)
          for (unsigned value = 0; value < 256; value += exhaustive ? 1 : 17) {
            for (size_t i = 0; i < bytes.size(); ++i) bytes[i] = uint8_t(0x81 + 29 * i);
            std::copy(seed.begin(), seed.end(), bytes.begin());
            bytes[at] = uint8_t(value);
            for (size_t n = 0; n <= bytes.size(); ++n) check(bytes, n);
          }
      }
      sections.emplace_back("mutations-truncations-mode-" + std::to_string(unsigned(mode)), checked - start);
      a.close(&ha); b.close(&hb);
    };
    run(CS_MODE_64, true);
    for (unsigned mode : {0u, unsigned(CS_MODE_16), unsigned(CS_MODE_32),
                         unsigned(CS_MODE_16 | CS_MODE_32 | CS_MODE_64),
                         unsigned(CS_MODE_32 | CS_MODE_64), unsigned(CS_MODE_16 | CS_MODE_64),
                         unsigned(CS_MODE_64 | CS_MODE_X86_AMD), unsigned(CS_MODE_64 | CS_MODE_X86_INTEL)})
      run(cs_mode(mode), false);
    std::printf("{\"profile\":\"%s\",\"checked\":%llu,\"successes\":%llu,\"public_outputs_equal\":true,\"sections\":[",
                argv[3], (unsigned long long)checked, (unsigned long long)successes);
    for (size_t i = 0; i < sections.size(); ++i)
      std::printf("%s{\"name\":\"%s\",\"count\":%llu}", i ? "," : "", sections[i].first.c_str(), (unsigned long long)sections[i].second);
    std::puts("]}");
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}
