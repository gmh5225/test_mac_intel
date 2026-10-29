//===-- BlockExceptionCleanup.cpp - Authored exception fixture ----*- C++
//-*-===//
// NeverD Decompiler
/// \file
/// Independently authored Block capture cleanup observations. This does not
/// execute WMF or certify original source values, ABI, permissions or effects.

#include <Block.h>
#include <array>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

static void require(bool Value, const char *What) {
  if (!Value) {
    std::fprintf(stderr, "authored exception fixture failure: %s errno=%d\n",
                 What, errno);
    std::fflush(stdout);
    std::fflush(stderr);
    std::exit(2);
  }
}

static void quoted(const char *Text) {
  std::putchar('"');
  for (const unsigned char *P = reinterpret_cast<const unsigned char *>(Text);
       *P; ++P) {
    if (*P == '"' || *P == '\\')
      std::putchar('\\');
    if (*P < 32)
      std::printf("\\u%04x", static_cast<unsigned>(*P));
    else
      std::putchar(*P);
  }
  std::putchar('"');
}

static void imageJSON(const mach_header *Header, const char *Path,
                      const char *ExpectedUUID) {
  require(Header && Header->magic == MH_MAGIC_64, "actual 64-bit loaded image");
  const auto *Cursor =
      reinterpret_cast<const unsigned char *>(Header) + sizeof(mach_header_64);
  const auto *End = Cursor + Header->sizeofcmds;
  char UUID[37]{};
  unsigned UUIDCount = 0;
  unsigned VersionCount = 0;
  uint32_t Platform = 0, MinOS = 0, SDK = 0, Tools = 0;
  for (uint32_t I = 0; I < Header->ncmds; ++I) {
    require(static_cast<size_t>(End - Cursor) >= sizeof(load_command),
            "loaded command header");
    const auto *Command = reinterpret_cast<const load_command *>(Cursor);
    require(Command->cmdsize >= sizeof(*Command) &&
                Command->cmdsize <= static_cast<size_t>(End - Cursor),
            "loaded command range");
    if (Command->cmd == LC_UUID) {
      require(Command->cmdsize == sizeof(uuid_command), "loaded UUID width");
      const auto *U = reinterpret_cast<const uuid_command *>(Command);
      std::snprintf(UUID, sizeof(UUID),
                    "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-"
                    "%02X%02X%02X%02X%02X%02X",
                    U->uuid[0], U->uuid[1], U->uuid[2], U->uuid[3], U->uuid[4],
                    U->uuid[5], U->uuid[6], U->uuid[7], U->uuid[8], U->uuid[9],
                    U->uuid[10], U->uuid[11], U->uuid[12], U->uuid[13],
                    U->uuid[14], U->uuid[15]);
      ++UUIDCount;
    }
    if (Command->cmd == LC_BUILD_VERSION) {
      require(Command->cmdsize >= sizeof(build_version_command),
              "loaded build-version width");
      const auto *V = reinterpret_cast<const build_version_command *>(Command);
      Platform = V->platform;
      MinOS = V->minos;
      SDK = V->sdk;
      Tools = V->ntools;
      ++VersionCount;
    }
    Cursor += Command->cmdsize;
  }
  require(Cursor == End && UUIDCount == 1 && VersionCount == 1 && Platform == 7,
          "complete current platform7 loaded header");
  if (ExpectedUUID)
    require(std::strcmp(UUID, ExpectedUUID) == 0,
            "actual loaded provider matches required static UUID");
  std::printf("{\"path\":");
  quoted(Path);
  std::printf(" ,\"uuid\":");
  quoted(UUID);
  std::printf(",\"cpu_type\":%u,\"cpu_subtype\":%u,\"ncmds\":%u,"
              "\"sizeofcmds\":%u,\"platform\":%u,\"minos_bits\":%u,"
              "\"sdk_bits\":%u,\"ntools\":%u}",
              Header->cputype, Header->cpusubtype, Header->ncmds,
              Header->sizeofcmds, Platform, MinOS, SDK, Tools);
}

static void providersBeforeCases(const char *CxxUUID) {
  struct Provider {
    const char *Name;
    const char *Path;
    const char *Symbol;
    const char *UUID;
  };
  const Provider Providers[] = {
      {"dispatch", "/usr/lib/system/libdispatch.dylib",
       "dispatch_source_set_event_handler",
       "42B50931-38D5-3A5D-90EF-0FD7239C408D"},
      {"Blocks", "/usr/lib/system/libsystem_blocks.dylib", "_Block_copy",
       "A5FDF1FF-B793-3574-8903-D24571EACD25"},
      {"compiler_rt", "/usr/lib/system/libcompiler_rt.dylib",
       "__gcc_personality_v0", "5539B26B-6FA7-341F-9C21-25F04BC8138B"},
      {"unwind", "/usr/lib/system/libunwind.dylib", "_Unwind_Resume",
       "C4187425-764F-3506-A411-5102B50AE804"},
      {"cxxabi_throw", "/usr/lib/libc++abi.dylib", "__cxa_throw", CxxUUID},
      {"cxxabi_personality", "/usr/lib/libc++abi.dylib", "__gxx_personality_v0",
       CxxUUID}};
  std::printf("{\"type\":\"actual_loaded_prerequisite\",\"providers\":[");
  bool First = true;
  for (const Provider &P : Providers) {
    void *Handle = dlopen(P.Path, RTLD_NOW | RTLD_LOCAL);
    require(Handle != nullptr, "current provider dlopen");
    void *Symbol = dlsym(Handle, P.Symbol);
    Dl_info Info{};
    require(Symbol && dladdr(Symbol, &Info) && Info.dli_fbase,
            "current symbol image identity");
    if (!First)
      std::putchar(',');
    First = false;
    std::printf("{\"name\":");
    quoted(P.Name);
    std::printf(",\"symbol\":");
    quoted(P.Symbol);
    std::printf(",\"image\":");
    imageJSON(static_cast<const mach_header *>(Info.dli_fbase), Info.dli_fname,
              P.UUID);
    std::putchar('}');
    // Keep the handle alive. No observed address is cast to a callable type.
  }
  std::printf("],\"probe_image\":");
  imageJSON(_dyld_get_image_header(0), _dyld_get_image_name(0), nullptr);
  std::printf(",\"original_provider_ABI_permission_qualified\":false}\n");
  std::fflush(stdout);
}

struct State;
struct AuthoredFailure {
  State *Owner;
  uint64_t Bits;
  int Phase;
  int Kind;
};

using Handler = void (^)(void);

struct State {
  const char *Case;
  int ThrowPhase;
  int ThrowKind;
  int Phase = 0;
  int NextId = 0;
  int Live = 0;
  int Constructs = 0;
  int Copies = 0;
  int Destroys = 0;
  int Attempts = 0;
  int Invokes = 0;
  int Caught = 0;
  int EventCount = 0;
  bool APIEntered = false;
  bool APIReturned = false;
  Handler Held = nullptr;

  State(const char *Name, int P, int K)
      : Case(Name), ThrowPhase(P), ThrowKind(K) {}

  void record(const char *Event, int Kind = -1, int Id = 0, int From = 0) {
    ++EventCount;
    std::printf(
        "{\"type\":\"event\",\"case\":\"%s\",\"event\":\"%s\","
        "\"phase\":%d,\"kind\":%d,\"id\":%d,\"from\":%d,"
        "\"live\":%d,\"constructs\":%d,\"copies\":%d,"
        "\"destroys\":%d,\"attempts\":%d,\"invokes\":%d,\"caught\":%d}\n",
        Case, Event, Phase, Kind, Id, From, Live, Constructs, Copies, Destroys,
        Attempts, Invokes, Caught);
    std::fflush(stdout);
  }

  int newId() { return ++NextId; }
  void construct(int Kind, int Id) {
    ++Constructs;
    ++Live;
    record("construct", Kind, Id);
  }
  void attempt(int Kind, int Id, int From) {
    ++Attempts;
    record("copy_attempt", Kind, Id, From);
    if (Phase == ThrowPhase && Kind == ThrowKind) {
      record("throw", Kind, Id, From);
      throw AuthoredFailure{this, 0x85a4b6c719d2003fULL, Phase, Kind};
    }
  }
  void copied(int Kind, int Id, int From) {
    ++Copies;
    ++Live;
    record("copy_success", Kind, Id, From);
  }
  void destroy(int Kind, int Id) {
    require(Live > 0, "positive live capture before destruction");
    ++Destroys;
    --Live;
    record("destroy", Kind, Id);
  }
  void caught(const AuthoredFailure &Failure) {
    require(Failure.Owner == this && Failure.Bits == 0x85a4b6c719d2003fULL &&
                Failure.Phase == ThrowPhase && Failure.Kind == ThrowKind,
            "typed authored exception identity and exact sentinel");
    ++Caught;
    record("caught", Failure.Kind);
  }
};

template <int Kind, size_t N> struct Capture {
  State *Owner;
  int Id;
  std::array<unsigned char, N> Bytes;
  explicit Capture(State *S) : Owner(S), Id(S->newId()) {
    for (size_t I = 0; I < N; ++I)
      Bytes[I] = static_cast<unsigned char>(I * 13 + Kind * 31 + 7);
    Owner->construct(Kind, Id);
  }
  Capture(const Capture &Other)
      : Owner(Other.Owner), Id(Owner->newId()), Bytes(Other.Bytes) {
    Owner->attempt(Kind, Id, Other.Id);
    Owner->copied(Kind, Id, Other.Id);
  }
  ~Capture() noexcept {
    verify();
    Owner->destroy(Kind, Id);
  }
  void verify() const {
    for (size_t I = 0; I < N; ++I)
      require(Bytes[I] == static_cast<unsigned char>(I * 13 + Kind * 31 + 7),
              "authored capture bytes preserved");
  }
};

static void install(State *S) {
  Capture<0, 8> A(S);
  Capture<1, 40> B(S);
  Handler Stack = ^{
    A.verify();
    B.verify();
    ++S->Invokes;
    S->record("invoke");
    if (S->ThrowPhase == 3) {
      S->record("throw");
      throw AuthoredFailure{S, 0x85a4b6c719d2003fULL, 3, -1};
    }
  };
  S->Phase = 2;
  S->APIEntered = true;
  S->record("API_enter");
  S->Held = Block_copy(Stack);
  require(S->Held != nullptr, "typed copied Block result");
  S->APIReturned = true;
  S->record("API_return");
}

static void *sourceThread(void *Raw) {
  State *S = static_cast<State *>(Raw);
  try {
    install(S);
  } catch (const AuthoredFailure &Failure) {
    S->caught(Failure);
    require(S->Live == 0 && S->Held == nullptr && !S->APIReturned,
            "source unwind destroys exactly constructed captures");
  } catch (...) {
    require(false, "unexpected source exception type");
  }
  return nullptr;
}

static void runCase(const char *Name, int ThrowPhase, int ThrowKind) {
  State S(Name, ThrowPhase, ThrowKind);
  const size_t Page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  const size_t StackBytes = 1024 * 1024;
  const size_t MapBytes = StackBytes + Page * 2;
  void *Mapping = mmap(nullptr, MapBytes, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON, -1, 0);
  require(Mapping != MAP_FAILED, "own source stack mapping");
  auto *Stack = static_cast<unsigned char *>(Mapping) + Page;
  require(mprotect(Mapping, Page, PROT_NONE) == 0 &&
              mprotect(Stack + StackBytes, Page, PROT_NONE) == 0,
          "own source stack guards");
  pthread_attr_t Attr;
  require(pthread_attr_init(&Attr) == 0 &&
              pthread_attr_setguardsize(&Attr, 0) == 0 &&
              pthread_attr_setstack(&Attr, Stack, StackBytes) == 0,
          "own pthread stack attributes");
  S.Phase = 1;
  S.record("case_begin");
  pthread_t Thread;
  require(pthread_create(&Thread, &Attr, sourceThread, &S) == 0,
          "new authored source pthread");
  require(pthread_attr_destroy(&Attr) == 0 &&
              pthread_join(Thread, nullptr) == 0,
          "source pthread completion");
  require(S.Live == (ThrowPhase == 1 || ThrowPhase == 2 ? 0 : 2),
          "exact capture count after source pthread exits");
  require(mprotect(Stack, StackBytes, PROT_NONE) == 0,
          "source stack becomes inaccessible");
  S.Phase = 3;
  S.record("source_stack_protected");
  if (S.Held) {
    try {
      S.Held();
      S.record("invoke_return");
    } catch (const AuthoredFailure &Failure) {
      S.caught(Failure);
      require(S.Live == 2, "invocation unwind retains two copied captures");
    } catch (...) {
      require(false, "unexpected invocation exception type");
    }
    S.Phase = 4;
    Block_release(S.Held);
    S.Held = nullptr;
  }
  require(S.Caught == (ThrowPhase == 0 ? 0 : 1),
          "exact finite authored exception count");
  require(S.Invokes == (ThrowPhase == 0 || ThrowPhase == 3 ? 1 : 0),
          "exact finite authored invocation count");
  require(S.Live == 0 && S.Destroys == S.Constructs + S.Copies,
          "balanced successful capture instances after cleanup");
  S.Phase = 5;
  S.record("all_captures_disposed");
  require(munmap(Mapping, MapBytes) == 0, "owned source stack disposal");
  std::printf(
      "{\"type\":\"case_result\",\"case\":\"%s\",\"throw_phase\":%d,"
      "\"throw_kind\":%d,\"constructs\":%d,\"copies\":%d,\"destroys\":%d,"
      "\"attempts\":%d,\"invokes\":%d,\"caught\":%d,\"final_live\":%d,"
      "\"API_entered\":%s,\"API_returned\":%s,\"events\":%d,"
      "\"source_stack_bytes\":%zu,\"source_stack_begin\":%llu,"
      "\"capture_sizes\":[%zu,%zu],"
      "\"source_stack_protected_through_remaining_cleanup\":true,"
      "\"original_WMF_ABI_value_permission_lifetime_effect_qualified\":false}"
      "\n",
      Name, ThrowPhase, ThrowKind, S.Constructs, S.Copies, S.Destroys,
      S.Attempts, S.Invokes, S.Caught, S.Live, S.APIEntered ? "true" : "false",
      S.APIReturned ? "true" : "false", S.EventCount, StackBytes,
      static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(Stack)),
      sizeof(Capture<0, 8>), sizeof(Capture<1, 40>));
  std::fflush(stdout);
}

int main(int Argc, char **Argv) {
  require(Argc == 2 && std::strlen(Argv[1]) == 36,
          "new candidate C++ ABI UUID provided by current static observer");
  providersBeforeCases(Argv[1]);
  runCase("stack_copy_kind0_throws", 1, 0);
  runCase("stack_copy_kind1_throws", 1, 1);
  runCase("heap_copy_kind0_throws", 2, 0);
  runCase("heap_copy_kind1_throws", 2, 1);
  runCase("invoke_throws_after_source_stack_protection", 3, -1);
  runCase("two_capture_ordinary_control", 0, -1);
  std::printf(
      "{\"type\":\"complete_new_authored_exception_domain\","
      "\"cases\":6,\"original_WMF_or_generated_C_executed\":false,"
      "\"original_source_ABI_effect_permission_or_increment\":false}\n");
  std::fflush(stdout);
  return 0;
}
