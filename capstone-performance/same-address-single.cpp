#include <algorithm>
#include <chrono>
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#ifdef __APPLE__
#include <pthread/qos.h>
#endif

#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <cstring>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#include <memory>
#include <capstone/capstone.h>
struct API {
  decltype(&::cs_open) cs_open;
  decltype(&::cs_option) cs_option;
  decltype(&::cs_malloc) cs_malloc;
  decltype(&::cs_disasm_iter) cs_disasm_iter;
  decltype(&::cs_regs_access) cs_regs_access;
  decltype(&::cs_free) cs_free;
  decltype(&::cs_close) cs_close;
  void *library;
  API(const std::string &path) {
    library = LoadLibraryA(path.c_str());
    if (!library) throw std::runtime_error("LoadLibrary " + std::to_string(GetLastError()));
    cs_open = reinterpret_cast<decltype(cs_open)>(GetProcAddress(static_cast<HMODULE>(library), "cs_open"));
    if (!cs_open) throw std::runtime_error("GetProcAddress cs_open");
    cs_option = reinterpret_cast<decltype(cs_option)>(GetProcAddress(static_cast<HMODULE>(library), "cs_option"));
    if (!cs_option) throw std::runtime_error("GetProcAddress cs_option");
    cs_malloc = reinterpret_cast<decltype(cs_malloc)>(GetProcAddress(static_cast<HMODULE>(library), "cs_malloc"));
    if (!cs_malloc) throw std::runtime_error("GetProcAddress cs_malloc");
    cs_disasm_iter = reinterpret_cast<decltype(cs_disasm_iter)>(GetProcAddress(static_cast<HMODULE>(library), "cs_disasm_iter"));
    if (!cs_disasm_iter) throw std::runtime_error("GetProcAddress cs_disasm_iter");
    cs_regs_access = reinterpret_cast<decltype(cs_regs_access)>(GetProcAddress(static_cast<HMODULE>(library), "cs_regs_access"));
    if (!cs_regs_access) throw std::runtime_error("GetProcAddress cs_regs_access");
    cs_free = reinterpret_cast<decltype(cs_free)>(GetProcAddress(static_cast<HMODULE>(library), "cs_free"));
    if (!cs_free) throw std::runtime_error("GetProcAddress cs_free");
    cs_close = reinterpret_cast<decltype(cs_close)>(GetProcAddress(static_cast<HMODULE>(library), "cs_close"));
    if (!cs_close) throw std::runtime_error("GetProcAddress cs_close");
  }
  ~API() { FreeLibrary(static_cast<HMODULE>(library)); }
};
static cs_insn *shared_insn = nullptr;
static cs_detail *shared_detail = nullptr;

struct Result {
  uint64_t instructions = 0, rejected = 0;
  uint64_t boundaries = 0xcbf29ce484222325ULL, values = 0;
};
static double process_cpu_ns() {
#ifdef _WIN32
  FILETIME created, exited, kernel, user;
  if (!GetProcessTimes(GetCurrentProcess(), &created, &exited, &kernel, &user))
    throw std::runtime_error("GetProcessTimes");
  auto ticks = [](FILETIME t) {
    return (uint64_t(t.dwHighDateTime) << 32) | t.dwLowDateTime;
  };
  return double(ticks(kernel) + ticks(user)) * 100;
#else
  const auto ticks = std::clock();
  if (ticks == std::clock_t(-1))
    throw std::runtime_error("clock");
  return double(ticks) * 1e9 / CLOCKS_PER_SEC;
#endif
}

static void record(Result &r, size_t offset, size_t length, bool ok) {
  r.boundaries =
      (r.boundaries ^ ((offset << 5) | (length << 1) | ok)) * 1099511628211ULL;
  if (ok)
    ++r.instructions;
  else
    ++r.rejected;
}
static void text_value(Result &r, const char *s) {
  size_t n = 0;
  while (s[n])
    ++n;
  r.values += n + (n ? static_cast<unsigned char>(s[n - 1]) : 0);
}

struct Session {
 const API &api; unsigned bits, mode; csh handle=0; cs_insn *insn=nullptr;
 Session(const API &a, unsigned b, unsigned m): api(a),bits(b),mode(m) {
  const cs_arch archs[] = {CS_ARCH_AARCH64, CS_ARCH_ARM, CS_ARCH_RISCV, CS_ARCH_PPC, CS_ARCH_MIPS, CS_ARCH_SYSTEMZ, CS_ARCH_XTENSA, CS_ARCH_XTENSA, CS_ARCH_XTENSA, CS_ARCH_XTENSA, CS_ARCH_SPARC, CS_ARCH_LOONGARCH, CS_ARCH_ARC, CS_ARCH_ARM};
  const cs_mode modes[] = {cs_mode(CS_MODE_LITTLE_ENDIAN), cs_mode(CS_MODE_ARM), cs_mode(CS_MODE_RISCV64 | CS_MODE_RISCV_C | CS_MODE_RISCV_FD | CS_MODE_RISCV_A), cs_mode(CS_MODE_64), cs_mode(CS_MODE_MIPS64), cs_mode(CS_MODE_BIG_ENDIAN), cs_mode(CS_MODE_XTENSA_ESP32), cs_mode(CS_MODE_XTENSA_ESP32S2), cs_mode(CS_MODE_XTENSA_ESP32S3), cs_mode(CS_MODE_XTENSA_ESP8266), cs_mode(CS_MODE_V9 | CS_MODE_BIG_ENDIAN), cs_mode(CS_MODE_LOONGARCH64), cs_mode(CS_MODE_LITTLE_ENDIAN), cs_mode(CS_MODE_THUMB)};
  if (bits != 32 && bits != 64 && bits >= sizeof(archs) / sizeof(archs[0])) throw std::runtime_error("architecture selector");
  if (api.cs_open(bits >= 16 ? CS_ARCH_X86 : archs[bits], bits == 64 ? CS_MODE_64 : bits == 32 ? CS_MODE_32 : modes[bits], &handle) != CS_ERR_OK)
    throw std::runtime_error("cs_open");
  if (api.cs_option(handle, CS_OPT_DETAIL, mode == 2 ? CS_OPT_ON : CS_OPT_OFF) !=
          CS_ERR_OK ||
      api.cs_option(handle, CS_OPT_TEXT, mode ? CS_OPT_ON : CS_OPT_OFF) !=
          CS_ERR_OK)
    throw std::runtime_error("cs_option");
  if (!shared_insn) {
    if (api.cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
      throw std::runtime_error("allocation detail option");
    shared_insn = api.cs_malloc(handle);
    if (!shared_insn || !shared_insn->detail) throw std::runtime_error("cs_malloc");
    shared_detail = shared_insn->detail;
    if (api.cs_option(handle, CS_OPT_DETAIL, mode == 2 ? CS_OPT_ON : CS_OPT_OFF) != CS_ERR_OK)
      throw std::runtime_error("restore detail option");
  }
  insn = shared_insn;
  std::memset(insn, 0, sizeof(*insn));
  std::memset(shared_detail, 0, sizeof(*shared_detail));
  insn->detail = mode == 2 ? shared_detail : nullptr;
 }
 ~Session(){api.cs_close(&handle);}

};
static Result run(Session &session,const std::vector<uint8_t>&bytes_,unsigned repeats){
 const API &api=session.api; csh handle=session.handle;cs_insn *insn=session.insn;unsigned mode=session.mode;
 const uint8_t *bytes=bytes_.data();size_t count=bytes_.size();
  Result result;
  for (unsigned repeat = 0; repeat < repeats; ++repeat) {
    const uint8_t *cursor = bytes;
    size_t left = count;
    uint64_t ip = 0x100000;
    while (left) {
      size_t offset = cursor - bytes;
      bool ok = api.cs_disasm_iter(handle, &cursor, &left, &ip, insn);
      record(result, offset, ok ? insn->size : 1, ok);
      if (!ok) {
        ++cursor;
        --left;
        ++ip;
        continue;
      }
      if (!insn->size)
        throw std::runtime_error("zero instruction length");
      result.values += insn->id;
      if (mode) {
        text_value(result, insn->mnemonic);
        text_value(result, insn->op_str);
      }
      if (mode == 2) {
        cs_regs read, written;
        uint8_t nr = 0, nw = 0;
        cs_err access = api.cs_regs_access(handle, insn, read, &nr, written, &nw);
        if (access != CS_ERR_OK && access != CS_ERR_ARCH)
          throw std::runtime_error("cs_regs_access " + std::to_string(access));
        result.values += static_cast<unsigned>(access);
        for (unsigned i = 0; i < nr; ++i)
          result.values += read[i];
        for (unsigned i = 0; i < nw; ++i)
          result.values += written[i];
        result.values += insn->detail->groups_count + insn->detail->regs_read_count + insn->detail->regs_write_count;
        if (session.bits == 11) {
          const auto &d = insn->detail->loongarch;
          for (unsigned i = 0; i < d.op_count; ++i) {
            const auto &o = d.operands[i];
            result.values += o.type + o.access;
            if (o.type == LOONGARCH_OP_REG) result.values += o.reg;
            if (o.type == LOONGARCH_OP_IMM) result.values += o.imm;
            if (o.type == LOONGARCH_OP_MEM) result.values += o.mem.base + o.mem.index + uint64_t(o.mem.disp);
          }
        } else if (session.bits == 12) {
          const auto &d = insn->detail->arc;
          for (unsigned i = 0; i < d.op_count; ++i) {
            const auto &o = d.operands[i];
            result.values += o.type + o.access;
            if (o.type == ARC_OP_REG) result.values += o.reg;
            if (o.type == ARC_OP_IMM) result.values += o.imm;
          }
        }
        if (session.bits >= 16) {
          const auto &x=insn->detail->x86;
          result.values += x.eflags;
          for (unsigned i=0;i<x.op_count;++i) {
            const auto &o=x.operands[i]; result.values += o.type + o.size + o.access;
            if(o.type==X86_OP_REG) result.values += o.reg;
            if(o.type==X86_OP_IMM) result.values += o.imm;
            if(o.type==X86_OP_MEM) result.values += uint64_t(o.mem.segment)+o.mem.base+o.mem.index+o.mem.scale+o.mem.disp;
          }
        }

      }
    }
  }
  return result;
}
static bool equal(const Result&a,const Result&b){return a.instructions==b.instructions&&a.rejected==b.rejected&&a.values==b.values&&a.boundaries==b.boundaries;}
int main() {
  try {
#ifdef __APPLE__
    if (pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0))
      throw std::runtime_error("QoS");
#endif
    DWORD_PTR mask, system;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &mask, &system) || !mask ||
        !SetThreadAffinityMask(GetCurrentThread(), mask & -mask))
      throw std::runtime_error("thread affinity");
    unsigned selector, mode, repeats;
    std::string corpus, library_path, last_library;
    std::map<std::string, std::vector<uint8_t>> inputs;
    while (std::cin >> std::quoted(library_path) >> selector >> mode >> std::quoted(corpus) >> repeats) {
    last_library = library_path;
    if (mode > 2 || !repeats) throw std::runtime_error("mode/repeats");
    API api(library_path);
    Session session(api, selector, mode);
    auto entry = inputs.find(corpus);
    if (entry == inputs.end()) {
      std::ifstream f(corpus, std::ios::binary);
      std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(f)), {});
      entry = inputs.emplace(corpus, std::move(bytes)).first;
    }
    const auto &bytes = entry->second;
    if (bytes.empty()) throw std::runtime_error("corpus");
    const Result first = run(session, bytes, 1);
    const Result expected = run(session, bytes, repeats);
    ULONG64 cycles_start, cycles_end;
    if (!QueryThreadCycleTime(GetCurrentThread(), &cycles_start)) throw std::runtime_error("cycle timer");
    auto wall = std::chrono::steady_clock::now();
    double cpu = process_cpu_ns();
    const Result measured = run(session, bytes, repeats);
    cpu = process_cpu_ns() - cpu;
    if (!QueryThreadCycleTime(GetCurrentThread(), &cycles_end)) throw std::runtime_error("cycle timer");
    double elapsed = std::chrono::duration<double, std::nano>(std::chrono::steady_clock::now() - wall).count();
    if (!equal(expected, measured)) throw std::runtime_error("sample mismatch");
    std::printf("{\"image_base\":%llu,\"stack\":%llu,\"processor\":%lu,",
        (unsigned long long)(uintptr_t)api.library,
        (unsigned long long)(uintptr_t)&cycles_start,
        (unsigned long)GetCurrentProcessorNumber());
    std::printf("\"output\":%llu,\"detail_storage\":%llu,\"input_storage\":%llu,\"handle\":%llu,",
      (unsigned long long)(uintptr_t)shared_insn, (unsigned long long)(uintptr_t)shared_detail,
      (unsigned long long)(uintptr_t)bytes.data(), (unsigned long long)session.handle);
    std::printf("\"selector\":%u,\"mode\":%u,\"repeats\":%u,\"thread_cycles\":%llu,\"cpu_ns\":%.0f,\"wall_ns\":%.0f,\"first\":{\"instructions\":%llu,\"rejected\":%llu,\"boundaries\":%llu,\"values\":%llu},\"result\":{\"instructions\":%llu,\"rejected\":%llu,\"boundaries\":%llu,\"values\":%llu}}\n",
      selector, mode, repeats, (unsigned long long)(cycles_end - cycles_start), cpu, elapsed,
      (unsigned long long)first.instructions, (unsigned long long)first.rejected,
      (unsigned long long)first.boundaries, (unsigned long long)first.values,
      (unsigned long long)measured.instructions, (unsigned long long)measured.rejected,
      (unsigned long long)measured.boundaries, (unsigned long long)measured.values);
    std::fflush(stdout);
    }
    if (!std::cin.eof()) throw std::runtime_error("request parse");
    if (shared_insn) {
      API api(last_library);
      shared_insn->detail = shared_detail;
      api.cs_free(shared_insn, 1);
    }
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what()); return 1;
  }
}
