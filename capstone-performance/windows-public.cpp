#include <capstone/capstone.h>
#include <array>
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

struct API {
  decltype(&::cs_open) open;
  decltype(&::cs_close) close;
  decltype(&::cs_option) option;
  decltype(&::cs_disasm_iter) iter;
  decltype(&::cs_errno) error;
  decltype(&::cs_regs_access) regs;
  explicit API(const char *p) {
    auto h = LoadLibraryA(p);
    if (!h) throw std::runtime_error(p);
#define LOAD(field, name) field = reinterpret_cast<decltype(field)>(GetProcAddress(h, name)); if (!field) throw std::runtime_error(name)
    LOAD(open, "cs_open"); LOAD(close, "cs_close");
    LOAD(option, "cs_option"); LOAD(iter, "cs_disasm_iter");
    LOAD(error, "cs_errno"); LOAD(regs, "cs_regs_access");
#undef LOAD
  }
};

struct Config { cs_arch arch; cs_mode mode; int syntax; const char *name; const char *path; };
const Config configs[] = {
  {CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_SYNTAX_DEFAULT, "armel-ls", "armel-ls.text"},
  {CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_SYNTAX_CS_REG_ALIAS, "armel-cp", "armel-cp.text"},
  {CS_ARCH_ARM, CS_MODE_ARM, CS_OPT_SYNTAX_NOREGNAME, "armel-sort", "armel-sort.text"},
  {CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_SYNTAX_DEFAULT, "armhf-ls", "armhf-ls.text"},
  {CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_SYNTAX_CS_REG_ALIAS, "armhf-cp", "armhf-cp.text"},
  {CS_ARCH_ARM, CS_MODE_THUMB, CS_OPT_SYNTAX_NOREGNAME, "armhf-sort", "armhf-sort.text"},
};
uint64_t rng = 0x91be8cd7c965a0f3ULL, compared = 0;
uint64_t random_word() { rng ^= rng << 13; rng ^= rng >> 7; rng ^= rng << 17; return rng; }
int main(int argc, char **argv) {
  try {
    if (argc != 5) throw std::runtime_error("baseline candidate iterations corpus-directory");
    API api[2] = {API(argv[1]), API(argv[2])};
    const unsigned iterations = std::stoul(argv[3]);
    for (const auto &config : configs) {
      if (std::getenv("ONLY_X86") && config.arch != CS_ARCH_X86) continue;
      for (unsigned output = 0; output < 4; ++output) {
        if (std::getenv("DETAIL_FLAGS") && output != 3) continue;
        csh handles[2] = {};
        cs_err opened[2];
        for (unsigned side = 0; side < 2; ++side)
          opened[side] = api[side].open(config.arch, config.mode, &handles[side]);
        if (opened[0] != opened[1]) throw std::runtime_error("mode admission mismatch");
        if (opened[0] != CS_ERR_OK) {
          std::printf("matching rejected mode %s output %u error %u\n", config.name, output, unsigned(opened[0]));
          continue;
        }
        for (unsigned side = 0; side < 2; ++side) {
          if (api[side].option(handles[side], CS_OPT_TEXT, (output & 1) ? CS_OPT_ON : CS_OPT_OFF) != CS_ERR_OK ||
              api[side].option(handles[side], CS_OPT_DETAIL, (output & 2) ? (std::getenv("DETAIL_FLAGS") ? std::strtoul(std::getenv("DETAIL_FLAGS"), nullptr, 0) : CS_OPT_ON) : CS_OPT_OFF) != CS_ERR_OK) throw std::runtime_error("options");
        }
        if (config.syntax >= 0) {
          cs_err syntax[2];
          for(unsigned side=0;side<2;++side) syntax[side]=api[side].option(handles[side], CS_OPT_SYNTAX, config.syntax);
          if(syntax[0]!=syntax[1]) throw std::runtime_error("syntax admission mismatch");
          if(syntax[0]!=CS_ERR_OK) {
            std::printf("matching rejected syntax %s output %u error %u\n",config.name,output,unsigned(syntax[0]));
            for(unsigned side=0;side<2;++side) api[side].close(&handles[side]);
            continue;
          }
        }
        if (std::getenv("CUSTOM_NAMES") && config.arch == CS_ARCH_ARM) {
          const unsigned ids[] = {ARM_INS_ADD, ARM_INS_MOV, ARM_INS_HINT, ARM_INS_POP, ARM_INS_BL};
          for (unsigned id : ids) for (unsigned side=0; side<2; ++side) {
            cs_opt_mnem value = {id, "custom|mnemonic with spaces and a long truncating suffix"};
            if (api[side].option(handles[side], CS_OPT_MNEMONIC, (size_t)&value) != CS_ERR_OK) throw std::runtime_error("custom mnemonic option");
          }
        }
        auto compare = [&](const uint8_t *bytes, size_t len, uint64_t address) {
          cs_insn insn[2]; cs_detail detail[2];
          bool ok[2]; size_t sizes[2] = {len, len};
          const uint8_t *p[2] = {bytes, bytes};
          uint64_t ip[2] = {address, address};
          cs_err err[2];
          for (unsigned side = 0; side < 2; ++side) {
            std::memset(&insn[side], 0xa5, sizeof(cs_insn));
            std::memset(&detail[side], 0xa5, sizeof(cs_detail));
            insn[side].detail = &detail[side];
            ok[side] = api[side].iter(handles[side], &p[side], &sizes[side], &ip[side], &insn[side]);
            err[side] = api[side].error(handles[side]);
            if (insn[side].detail != &detail[side]) throw std::runtime_error("detail restoration");
          }
          bool mismatch = ok[0] != ok[1] || p[0] != p[1] || sizes[0] != sizes[1] || ip[0] != ip[1] || err[0] != err[1];
          insn[0].detail = insn[1].detail = nullptr;
          mismatch |= std::memcmp(&insn[0], &insn[1], sizeof(cs_insn)) != 0;
          mismatch |= std::memcmp(&detail[0], &detail[1], sizeof(cs_detail)) != 0;
          if (ok[0] && ok[1] && (output & 2)) {
            cs_regs read[2] = {}, write[2] = {}; uint8_t nr[2] = {}, nw[2] = {};
            for (unsigned side = 0; side < 2; ++side) {
              insn[side].detail = &detail[side];
              err[side] = api[side].regs(handles[side], &insn[side], read[side], &nr[side], write[side], &nw[side]);
            }
            mismatch |= err[0] != err[1] || nr[0] != nr[1] || nw[0] != nw[1] || std::memcmp(read[0], read[1], sizeof(cs_regs)) || std::memcmp(write[0], write[1], sizeof(cs_regs));
          }
          if (mismatch) {
            std::fprintf(stderr, "mismatch %s output=%u count=%llu len=%zu address=%llx ok=%d/%d id=%u/%u bytes=", config.name, output, (unsigned long long)compared, len, (unsigned long long)address, ok[0], ok[1], insn[0].id, insn[1].id);
            for (size_t j=0;j<len && j<16;++j) std::fprintf(stderr,"%02x",bytes[j]);
            std::fprintf(stderr,"\n"); throw std::runtime_error("semantic mismatch");
          }
          ++compared;
          return ok[0] ? size_t(p[0] - bytes) : size_t(1);
        };
        SYSTEM_INFO info;
        GetSystemInfo(&info);
        const size_t page = info.dwPageSize;
        void *mapping = VirtualAlloc(nullptr, page * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        DWORD previous = 0;
        if (!mapping || !VirtualProtect(static_cast<uint8_t *>(mapping) + page, page, PAGE_NOACCESS, &previous))
          throw std::runtime_error("guard pages");
        for (unsigned i = 0; i < 32; ++i) {
          for (size_t len = 0; len <= 16; ++len) {
            uint8_t *tail = static_cast<uint8_t *>(mapping) + page - len;
            for (size_t j = 0; j < len; ++j) tail[j] = random_word();
            compare(tail, len, UINT64_MAX - i);
          }
        }
        if (!VirtualFree(mapping, 0, MEM_RELEASE)) throw std::runtime_error("VirtualFree");
        std::array<uint8_t, 16> bytes;
        for (unsigned i = 0; i < iterations; ++i) {
          for (unsigned j = 0; j < 16; j += 8) { uint64_t w = random_word(); std::memcpy(bytes.data()+j, &w, 8); }
          if (i < 65536) { bytes[0] = i; bytes[1] = i >> 8; }
          size_t len = (i & 31) < 16 ? (i & 31) : 16;
          compare(bytes.data(), len, (i & 1) ? UINT64_MAX - (i & 7) : 0x100000 + i * 4);
        }
        std::string path = std::string(argv[4]) + "/" + config.path;
        std::ifstream file(path, std::ios::binary); if (!file) throw std::runtime_error(path);
        std::vector<uint8_t> corpus((std::istreambuf_iterator<char>(file)), {});
        for (size_t pos = 0; pos < corpus.size();) pos += compare(corpus.data()+pos, corpus.size()-pos, 0x100000 + pos);
        for (unsigned side = 0; side < 2; ++side) api[side].close(&handles[side]);
        std::printf("{\"config\":\"%s\",\"output\":%u,\"compared_total\":%llu}\n", config.name, output, (unsigned long long)compared); std::fflush(stdout);
      }
    }
  } catch(const std::exception &e) { std::fprintf(stderr, "%s\n", e.what()); return 1; }
}
