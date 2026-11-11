//===- compare.cpp - Compare x86 decoder API workloads -------------------===//
//
// NeverD Decompiler
//
//===----------------------------------------------------------------------===//
/// \file
/// Compare x86 decoder API workloads. Benchmark-only; not linked into NeverD.

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>
#ifdef __APPLE__
#include <pthread/qos.h>
#endif
#ifdef USE_BATCH
#include "arch/X86/X86ScanAdapter.h"
#endif

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

#include <capstone/capstone.h>

struct Result {
  uint64_t instructions = 0, rejected = 0;
  uint64_t boundaries = 0xcbf29ce484222325ULL, values = 0;
};
extern "C" void *iced_create(unsigned bits, unsigned mode);
extern "C" void iced_run(void *, const uint8_t *, size_t, unsigned, Result *);
extern "C" void iced_destroy(void *);

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

static Result capstone_run(const uint8_t *bytes, size_t count, unsigned bits,
                           unsigned mode, unsigned repeats) {
  csh handle = 0;
  cs_mode m = bits == 64 ? CS_MODE_64 : bits == 32 ? CS_MODE_32 : CS_MODE_16;
  if (cs_open(CS_ARCH_X86, m, &handle) != CS_ERR_OK)
    throw std::runtime_error("cs_open");
  if (cs_option(handle, CS_OPT_DETAIL, mode == 2 ? CS_OPT_ON : CS_OPT_OFF) !=
          CS_ERR_OK ||
      cs_option(handle, CS_OPT_TEXT, mode ? CS_OPT_ON : CS_OPT_OFF) !=
          CS_ERR_OK)
    throw std::runtime_error("cs_option");
  cs_insn *insn = cs_malloc(handle);
  if (!insn)
    throw std::runtime_error("cs_malloc");
  Result result;
#ifdef USE_BATCH
  if (mode == 0) {
    for (unsigned repeat = 0; repeat < repeats; ++repeat) {
      const uint8_t *cursor = bytes;
      size_t left = count;
      uint64_t ip = 0x100000;
      while (left) {
        uint32_t output[64];
        const auto batch = X86_scanBatch(handle, cursor, left, ip, output, 64);
        size_t accepted = batch.count;
        for (size_t i = 0; i < accepted; ++i) {
          size_t length = output[i] & 255;
          record(result, cursor - bytes, length, true);
          result.values += output[i] >> 8;
          cursor += length; left -= length; ip += length;
        }
        if (accepted != 64 && left) {
          record(result, cursor - bytes, 1, false);
          ++cursor; --left; ++ip;
        }
      }
    }
    cs_free(insn, 1); cs_close(&handle);
    return result;
  }
#endif
  for (unsigned repeat = 0; repeat < repeats; ++repeat) {
    const uint8_t *cursor = bytes;
    size_t left = count;
    uint64_t ip = 0x100000;
    while (left) {
      size_t offset = cursor - bytes;
      bool ok = cs_disasm_iter(handle, &cursor, &left, &ip, insn);
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
        if (cs_regs_access(handle, insn, read, &nr, written, &nw) != CS_ERR_OK)
          throw std::runtime_error("cs_regs_access");
        for (unsigned i = 0; i < nr; ++i)
          result.values += read[i];
        for (unsigned i = 0; i < nw; ++i)
          result.values += written[i];
        const auto &x = insn->detail->x86;
        result.values += x.eflags + insn->detail->groups_count;
        for (unsigned i = 0; i < x.op_count; ++i) {
          const auto &o = x.operands[i];
          result.values += o.type + o.size + o.access;
          if (o.type == X86_OP_REG)
            result.values += o.reg;
          if (o.type == X86_OP_IMM)
            result.values += o.imm;
          if (o.type == X86_OP_MEM)
            result.values += uint64_t(o.mem.segment) + o.mem.base +
                             o.mem.index + o.mem.scale + o.mem.disp;
        }
      }
    }
  }
  cs_free(insn, 1);
  cs_close(&handle);
  return result;
}

int main(int argc, char **argv) {
#ifdef __APPLE__
  if (pthread_set_qos_class_self_np(QOS_CLASS_USER_INTERACTIVE, 0)) return 2;
#endif
  try {
    if (argc != 6)
      throw std::runtime_error("usage: compare capstone|iced "
                               "scan|format|detail BITS REPEATS INPUT");
    std::string library = argv[1], mode_name = argv[2];
    unsigned mode = mode_name == "scan"     ? 0
                    : mode_name == "format" ? 1
                    : mode_name == "detail" ? 2
                                            : 99;
    unsigned bits = std::stoul(argv[3]), repeats = std::stoul(argv[4]);
    if (mode > 2 || (bits != 16 && bits != 32 && bits != 64) || !repeats)
      throw std::runtime_error("invalid benchmark option");
    std::ifstream file(argv[5], std::ios::binary);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),
                               std::istreambuf_iterator<char>()};
    if (bytes.empty())
      throw std::runtime_error("empty or unreadable input");
    void *iced = iced_create(bits, mode);
    auto run = [&](unsigned n) {
      if (library == "capstone")
        return capstone_run(bytes.data(), bytes.size(), bits, mode, n);
      if (library == "iced") {
        Result r;
        iced_run(iced, bytes.data(), bytes.size(), n, &r);
        return r;
      }
      throw std::runtime_error("unknown library");
    };
    Result warm = run(1);
    ULONG64 cycles_start, cycles_end;
    DWORD_PTR available, system;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &available, &system) || !available ||
        !SetThreadAffinityMask(GetCurrentThread(), available & -available))
      throw std::runtime_error("affinity");
    if (!QueryThreadCycleTime(GetCurrentThread(), &cycles_start))
      throw std::runtime_error("QueryThreadCycleTime start");
    auto cpu_start = process_cpu_ns();
    auto start = std::chrono::steady_clock::now();
    Result result = run(repeats);
    auto end = std::chrono::steady_clock::now();
    auto cpu_end = process_cpu_ns();
    if (!QueryThreadCycleTime(GetCurrentThread(), &cycles_end))
      throw std::runtime_error("QueryThreadCycleTime end");
    iced_destroy(iced);
    if (result.instructions != warm.instructions * repeats ||
        result.rejected != warm.rejected * repeats)
      throw std::runtime_error("unstable traversal");
    std::printf("{\"library\":\"%s\",\"mode\":\"%s\",\"bits\":%u,\"repeats\":%"
                "u,\"bytes\":%zu,\"instructions\":%llu,\"rejected\":%llu,"
                "\"boundary_hash\":\"%016llx\",\"value_hash\":\"%016llx\","
                "\"thread_cycles\":%llu,\"wall_ns\":%lld,\"cpu_ns\":%.0f}\n",
                library.c_str(), mode_name.c_str(), bits, repeats, bytes.size(),
                (unsigned long long)result.instructions,
                (unsigned long long)result.rejected,
                (unsigned long long)result.boundaries,
                (unsigned long long)result.values,
                (unsigned long long)(cycles_end - cycles_start),
                (long long)std::chrono::duration_cast<std::chrono::nanoseconds>(
                    end - start)
                    .count(),
                cpu_end - cpu_start);
    return 0;
  } catch (const std::exception &e) {
    std::fprintf(stderr, "%s\n", e.what());
    return 1;
  }
}
