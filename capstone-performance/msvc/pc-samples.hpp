// Sample the benchmark thread and resolve the captured PCs after it has finished.
#include <dbghelp.h>
#include <atomic>
#include <array>
#include <map>
#include <thread>
#include <filesystem>
#include <system_error>

class PcSamples {
  HANDLE worker = nullptr;
  std::thread observer;
  std::atomic_bool stopping{false};
  const char *output = std::getenv("CAPSTONE_PC_SAMPLES");
  std::vector<DWORD64> samples;
  DWORD error = 0;

  void observe(DWORD_PTR mask) {
    SetThreadAffinityMask(GetCurrentThread(), mask);
    HANDLE timer = CreateWaitableTimerExW(nullptr, nullptr, CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS);
    if (!timer) { error = GetLastError(); return; }
    unsigned phase = 0x8ca31d1u;
    while (!stopping.load(std::memory_order_relaxed)) {
      // Vary the interval to avoid favoring the same part of a short loop.
      phase = 1664525u * phase + 1013904223u;
      LARGE_INTEGER due;
      due.QuadPart = -(7000 + static_cast<int>(phase >> 20));
      if (!SetWaitableTimer(timer, &due, 0, nullptr, nullptr, FALSE) ||
          WaitForSingleObject(timer, 100) != WAIT_OBJECT_0) { error = GetLastError() ? GetLastError() : ERROR_TIMEOUT; break; }
      if (stopping.load(std::memory_order_relaxed)) break;
      CONTEXT context{};
      context.ContextFlags = CONTEXT_CONTROL;
      if (SuspendThread(worker) == DWORD(-1)) { error = GetLastError(); break; }
      BOOL read = GetThreadContext(worker, &context);
      DWORD last = read ? 0 : GetLastError();
      if (ResumeThread(worker) == DWORD(-1)) std::abort();
      if (!read) { error = last; break; }
      samples.push_back(context.Rip);
    }
    CloseHandle(timer);
  }

public:
  void start() {
    if (!output) return;
    DWORD_PTR available, system;
    if (!GetProcessAffinityMask(GetCurrentProcess(), &available, &system))
      throw std::runtime_error("GetProcessAffinityMask");
    DWORD_PTR others = available & (available - 1);
    if (!others) throw std::runtime_error("sampling requires two available logical CPUs");
    if (!DuplicateHandle(GetCurrentProcess(), GetCurrentThread(), GetCurrentProcess(),
                         &worker, 0, FALSE, DUPLICATE_SAME_ACCESS))
      throw std::runtime_error("DuplicateHandle");
    samples.reserve(12000);
    observer = std::thread([this, others]{ observe(others & -others); });
  }
  void finish() {
    if (!output) return;
    stopping.store(true, std::memory_order_relaxed);
    observer.join(); CloseHandle(worker);
    if (error || samples.size() < 100) throw std::runtime_error("failed or undersampled benchmark thread");
    char executable[MAX_PATH];
    if (!GetModuleFileNameA(nullptr, executable, MAX_PATH)) throw std::runtime_error("GetModuleFileName");
    auto search = std::filesystem::path(executable).parent_path().string();
    HANDLE process = GetCurrentProcess();
    SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_UNDNAME |
                  SYMOPT_FAIL_CRITICAL_ERRORS | SYMOPT_NO_PROMPTS);
    if (!SymInitialize(process, search.c_str(), TRUE)) throw std::runtime_error("SymInitialize");
    std::map<DWORD64,unsigned> counts;
    for (auto pc : samples) ++counts[pc];
    std::ofstream out(output);
    out << "count\tmodule\trva\tsymbol\tfile\tline\n";
    for (auto [pc, count] : counts) {
      alignas(SYMBOL_INFO) std::array<char,sizeof(SYMBOL_INFO) + MAX_SYM_NAME> storage{};
      auto symbol = reinterpret_cast<SYMBOL_INFO*>(storage.data());
      symbol->SizeOfStruct = sizeof(*symbol); symbol->MaxNameLen = MAX_SYM_NAME;
      DWORD64 displacement = 0;
      bool has_symbol = SymFromAddr(process, pc, &displacement, symbol);
      IMAGEHLP_LINE64 line{}; line.SizeOfStruct = sizeof(line);
      DWORD offset = 0; bool has_line = SymGetLineFromAddr64(process, pc, &offset, &line);
      IMAGEHLP_MODULE64 module{}; module.SizeOfStruct = sizeof(module);
      bool has_module = SymGetModuleInfo64(process, pc, &module);
      out << count << '\t' << (has_module ? module.ModuleName : "?") << '\t'
          << std::hex << pc - (has_module ? module.BaseOfImage : 0) << std::dec << '\t'
          << (has_symbol ? symbol->Name : "?") << '\t' << (has_line ? line.FileName : "?")
          << '\t' << (has_line ? line.LineNumber : 0) << '\n';
    }
    if (!out) throw std::runtime_error("writing PC samples");
    SymCleanup(process);
  }
};
