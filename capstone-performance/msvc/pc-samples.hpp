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
  struct Frame { DWORD64 ip, caller; };
  struct Module { DWORD64 base; DWORD size; PRUNTIME_FUNCTION table; size_t count; };
  std::vector<Module> images;
  std::vector<Frame> samples;

  DWORD64 caller_pc(CONTEXT context) const {
    for (const auto& image : images) {
      if (context.Rip < image.base || context.Rip - image.base >= image.size) continue;
      auto rva = DWORD(context.Rip - image.base);
      auto entries = image.table;
      if (image.count) {
        auto upper = std::upper_bound(entries, entries + image.count, rva,
          [](DWORD address, const RUNTIME_FUNCTION &entry){ return address < entry.BeginAddress; });
        if (upper != entries && rva < (upper - 1)->EndAddress) {
          PVOID handler_data = nullptr;
          DWORD64 frame = 0;
          RtlVirtualUnwind(UNW_FLAG_NHANDLER, image.base, context.Rip, upper - 1,
                           &context, &handler_data, &frame, nullptr);
          return context.Rip;
        }
      }
      return *reinterpret_cast<const DWORD64*>(context.Rsp);
    }
    return 0;
  }

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
      context.ContextFlags = CONTEXT_FULL;
      if (SuspendThread(worker) == DWORD(-1)) { error = GetLastError(); break; }
      BOOL read = GetThreadContext(worker, &context);
      DWORD last = read ? 0 : GetLastError();
      DWORD64 caller = read ? caller_pc(context) : 0;
      if (ResumeThread(worker) == DWORD(-1)) std::abort();
      if (!read) { error = last; break; }
      samples.push_back({context.Rip, caller});
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
    for (const char *name : {static_cast<const char*>(nullptr), "vcruntime140.dll", "ucrtbase.dll"}) {
      auto base = reinterpret_cast<const BYTE*>(GetModuleHandleA(name));
      if (!base) continue;
      auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
      auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
      const auto &directory = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION];
      images.push_back({reinterpret_cast<DWORD64>(base), nt->OptionalHeader.SizeOfImage,
         reinterpret_cast<PRUNTIME_FUNCTION>(const_cast<BYTE*>(base + directory.VirtualAddress)),
         directory.Size / sizeof(RUNTIME_FUNCTION)});
    }
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
    std::map<std::pair<DWORD64,DWORD64>,unsigned> counts;
    for (auto sample : samples) ++counts[{sample.ip,sample.caller}];
    std::ofstream out(output);
    out << "count\tmodule\trva\tsymbol\tfile\tline\tcaller_module\tcaller_rva\tcaller_symbol\tcaller_disp\n";
    for (auto [pair, count] : counts) {
      auto [pc, caller] = pair;
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
          << '\t' << (has_line ? line.LineNumber : 0);
      IMAGEHLP_MODULE64 caller_module{}; caller_module.SizeOfStruct = sizeof(caller_module);
      bool resolved_module = caller && SymGetModuleInfo64(process, caller - 1, &caller_module);
      bool resolved = caller && SymFromAddr(process,caller-1,&displacement,symbol);
      out << '\t' << (resolved_module ? caller_module.ModuleName : "?")
          << '\t' << std::hex << caller-(resolved_module?caller_module.BaseOfImage:0) << std::dec
          << '\t' << (resolved?symbol->Name:"?") << '\t' << (resolved?displacement+1:0) << '\n';
    }
    if (!out) throw std::runtime_error("writing PC samples");
    SymCleanup(process);
  }
};
