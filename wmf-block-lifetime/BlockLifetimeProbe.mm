#include <Block.h>
#import <Foundation/Foundation.h>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <initializer_list>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <sys/mman.h>
#include <unistd.h>

static NSDictionary *imageInfo(const struct mach_header *header,
                               const char *path) {
  NSMutableDictionary *result = [NSMutableDictionary dictionary];
  result[@"path"] = path ? [NSString stringWithUTF8String:path] : @"";
  result[@"magic"] = @(header->magic);
  result[@"cpu_type"] = @(header->cputype);
  result[@"cpu_subtype"] = @(header->cpusubtype);
  result[@"ncmds"] = @(header->ncmds);
  result[@"sizeofcmds"] = @(header->sizeofcmds);
  if (header->magic != MH_MAGIC_64) {
    result[@"supported_header"] = @NO;
    return result;
  }
  result[@"supported_header"] = @YES;
  const unsigned char *cursor =
      (const unsigned char *)header + sizeof(struct mach_header_64);
  const unsigned char *end = cursor + header->sizeofcmds;
  NSMutableArray *versions = [NSMutableArray array];
  for (uint32_t i = 0; i < header->ncmds; ++i) {
    if ((size_t)(end - cursor) < sizeof(struct load_command)) {
      result[@"malformed_commands"] = @YES;
      break;
    }
    const struct load_command *command = (const struct load_command *)cursor;
    if (command->cmdsize < sizeof(*command) ||
        command->cmdsize > (size_t)(end - cursor)) {
      result[@"malformed_commands"] = @YES;
      break;
    }
    if (command->cmd == LC_UUID &&
        command->cmdsize >= sizeof(struct uuid_command)) {
      const struct uuid_command *uuid = (const struct uuid_command *)command;
      result[@"uuid"] =
          [[[NSUUID alloc] initWithUUIDBytes:uuid->uuid] UUIDString];
    }
    if (command->cmd == LC_BUILD_VERSION &&
        command->cmdsize >= sizeof(struct build_version_command)) {
      const struct build_version_command *version =
          (const struct build_version_command *)command;
      [versions addObject:@{
        @"platform" : @(version->platform),
        @"minos_bits" : @(version->minos),
        @"sdk_bits" : @(version->sdk),
        @"ntools" : @(version->ntools)
      }];
    }
    cursor += command->cmdsize;
  }
  result[@"build_versions"] = versions;
  return result;
}

static void require(bool value, const char *what) {
  if (!value) {
    fprintf(stderr, "authored fixture failure: %s errno=%d\n", what, errno);
    fflush(stdout);
    fflush(stderr);
    exit(2);
  }
}

static void emit(NSDictionary *object) {
  NSError *error = nil;
  NSData *data = [NSJSONSerialization dataWithJSONObject:object
                                                 options:0
                                                   error:&error];
  require(data != nil, "JSON serialization");
  fwrite(data.bytes, 1, data.length, stdout);
  fputc('\n', stdout);
  fflush(stdout);
}

using Handler = void (^)(void);
struct Event {
  const char *kind = nullptr;
  int stage = 0;
  int live = 0;
  int constructs = 0;
  int copies = 0;
  int destroys = 0;
};

struct State {
  const char *mode;
  size_t payloadBytes;
  std::atomic<int> live{0}, constructs{0}, copies{0}, destroys{0}, invokes{0},
      stage{0};
  std::atomic<unsigned> eventCount{0};
  std::array<Event, 64> events{};
  Handler held = nil;
  dispatch_queue_t queue = nullptr;
  dispatch_source_t source = nullptr;
  dispatch_semaphore_t fired = dispatch_semaphore_create(0);
  dispatch_semaphore_t disposed = dispatch_semaphore_create(0);
  dispatch_semaphore_t cancelled = dispatch_semaphore_create(0);
  int copiesBeforeAPI = -1;
  int copiesAfterAPI = -1;

  State(const char *m, size_t n) : mode(m), payloadBytes(n) {}
  void record(const char *kind) {
    unsigned index = eventCount.fetch_add(1);
    require(index < events.size(), "authored fixed event storage");
    events[index] = {kind,          stage.load(),
                     live.load(),   constructs.load(),
                     copies.load(), destroys.load()};
  }
  void construct() {
    constructs.fetch_add(1);
    live.fetch_add(1);
    record("construct");
  }
  void copy() {
    copies.fetch_add(1);
    live.fetch_add(1);
    record("copy");
  }
  void destroy() {
    destroys.fetch_add(1);
    int old = live.fetch_sub(1);
    require(old > 0, "valid authored capture destruction");
    record("destroy");
    if (old == 1)
      dispatch_semaphore_signal(disposed);
  }
  void invoke() {
    require(stage.load() == 3, "callback runs after source-stack protection");
    require(live.load() > 0, "live authored copied capture");
    invokes.fetch_add(1);
    record("invoke");
    dispatch_semaphore_signal(fired);
  }
};

template <size_t N> struct Capture {
  State *state;
  std::array<unsigned char, N> bytes;
  explicit Capture(State *s) : state(s) {
    for (size_t i = 0; i < N; ++i)
      bytes[i] = static_cast<unsigned char>(i * 17 + 3);
    state->construct();
  }
  Capture(const Capture &other) noexcept
      : state(other.state), bytes(other.bytes) {
    state->copy();
  }
  ~Capture() { state->destroy(); }
  void touch() const {
    for (size_t i = 0; i < N; ++i)
      require(bytes[i] == static_cast<unsigned char>(i * 17 + 3),
              "authored capture payload");
    state->invoke();
  }
};

template <> struct Capture<0> {
  State *state;
  explicit Capture(State *s) : state(s) { state->construct(); }
  Capture(const Capture &other) noexcept : state(other.state) { state->copy(); }
  ~Capture() { state->destroy(); }
  void touch() const { state->invoke(); }
};
static_assert(sizeof(Capture<0>) == 8);
static_assert(sizeof(Capture<24>) == 32);
static_assert(sizeof(Capture<72>) == 80);

template <size_t N> static void install(State *state) {
  Capture<N> capture(state);
  Handler stackHandler = ^{
    capture.touch();
  };
  state->copiesBeforeAPI = state->copies.load();
  if (strcmp(state->mode, "direct_copy") == 0) {
    state->held = Block_copy(stackHandler);
    require(state->held != nil, "typed Block_copy result");
  } else {
    dispatch_source_set_event_handler(state->source, stackHandler);
  }
  state->copiesAfterAPI = state->copies.load();
  require(state->copiesAfterAPI == state->copiesBeforeAPI + 1,
          "one synchronous capture copy during API");
  state->record("API_return");
}

static void *sourceThread(void *raw) {
  State *state = static_cast<State *>(raw);
  if (state->payloadBytes == 0)
    install<0>(state);
  else if (state->payloadBytes == 24)
    install<24>(state);
  else if (state->payloadBytes == 72)
    install<72>(state);
  else
    require(false, "authored payload choice");
  return nullptr;
}

static void cancelCallback(void *raw) {
  State *state = static_cast<State *>(raw);
  state->record("cancel_callback");
  dispatch_semaphore_signal(state->cancelled);
}

static void waitFor(dispatch_semaphore_t semaphore, const char *what) {
  require(dispatch_semaphore_wait(
              semaphore, dispatch_time(DISPATCH_TIME_NOW, 20 * NSEC_PER_SEC)) ==
              0,
          what);
}

static NSDictionary *runCase(const char *mode, size_t payloadBytes) {
  State state(mode, payloadBytes);
  const bool usesSource = strcmp(mode, "dispatch_source") == 0;
  if (usesSource) {
    state.queue = dispatch_queue_create("authored.WMF.BlockLifetime",
                                        DISPATCH_QUEUE_SERIAL);
    state.source = dispatch_source_create(DISPATCH_SOURCE_TYPE_DATA_ADD, 0, 0,
                                          state.queue);
    require(state.queue && state.source, "authored source creation");
    dispatch_set_context(state.source, &state);
    dispatch_source_set_cancel_handler_f(state.source, cancelCallback);
  }
  const size_t page = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  const size_t stackBytes = 1024 * 1024;
  const size_t mapBytes = stackBytes + 2 * page;
  void *mapping = mmap(nullptr, mapBytes, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANON, -1, 0);
  require(mapping != MAP_FAILED, "authored thread-stack mmap");
  unsigned char *stack = static_cast<unsigned char *>(mapping) + page;
  require(mprotect(mapping, page, PROT_NONE) == 0, "lower owned guard page");
  require(mprotect(stack + stackBytes, page, PROT_NONE) == 0,
          "upper owned guard page");
  pthread_attr_t attr;
  require(pthread_attr_init(&attr) == 0, "thread attributes");
  require(pthread_attr_setguardsize(&attr, 0) == 0,
          "custom stack guard policy");
  require(pthread_attr_setstack(&attr, stack, stackBytes) == 0,
          "owned thread stack");
  state.stage.store(1);
  pthread_t thread;
  require(pthread_create(&thread, &attr, sourceThread, &state) == 0,
          "source thread creation");
  require(pthread_attr_destroy(&attr) == 0, "thread attributes destruction");
  require(pthread_join(thread, nullptr) == 0, "source thread completion");
  require(state.live.load() == 1,
          "exactly copied capture remains after source thread exits");
  require(state.invokes.load() == 0, "no callback before activation");
  state.stage.store(2);
  state.record("source_thread_joined");
  require(mprotect(stack, stackBytes, PROT_NONE) == 0,
          "source stack becomes inaccessible");
  emit(@{
    @"type" : @"source_stack_protected",
    @"mode" : @(mode),
    @"payload_bytes" : @(payloadBytes),
    @"live" : @(state.live.load()),
    @"copies" : @(state.copies.load()),
    @"source_stack_begin" : @((uintptr_t)stack),
    @"source_stack_bytes" : @(stackBytes)
  });
  state.stage.store(3);
  if (usesSource) {
    dispatch_resume(state.source);
    dispatch_source_merge_data(state.source, 1);
  } else {
    state.held();
  }
  waitFor(state.fired, "copied callback completion");
  require(state.invokes.load() == 1, "one authored callback");
  state.stage.store(4);
  if (usesSource) {
    dispatch_source_cancel(state.source);
    waitFor(state.cancelled, "owned source cancellation");
    dispatch_release(state.source);
    state.source = nullptr;
    dispatch_sync(state.queue, ^{
                  });
  } else {
    Block_release(state.held);
    state.held = nil;
  }
  waitFor(state.disposed, "copied capture disposal");
  require(state.live.load() == 0, "all authored captures destroyed");
  require(state.destroys.load() ==
              state.constructs.load() + state.copies.load(),
          "balanced actual capture lifetimes");
  state.stage.store(5);
  state.record("all_captures_disposed");
  require(munmap(mapping, mapBytes) == 0, "owned stack mapping disposal");
  NSMutableArray *events = [NSMutableArray array];
  for (unsigned i = 0; i < state.eventCount.load(); ++i) {
    const Event &event = state.events[i];
    [events addObject:@{
      @"kind" : @(event.kind),
      @"stage" : @(event.stage),
      @"live" : @(event.live),
      @"constructs" : @(event.constructs),
      @"copies" : @(event.copies),
      @"destroys" : @(event.destroys)
    }];
  }
  NSDictionary *result = @{
    @"type" : @"authored_case",
    @"mode" : @(mode),
    @"payload_bytes" : @(payloadBytes),
    @"Cxx_capture_bytes" :
        @(payloadBytes == 0 ? sizeof(Capture<0>)
                            : (payloadBytes == 24 ? sizeof(Capture<24>)
                                                  : sizeof(Capture<72>))),
    @"copies_before_API" : @(state.copiesBeforeAPI),
    @"copies_after_API" : @(state.copiesAfterAPI),
    @"constructs" : @(state.constructs.load()),
    @"copies" : @(state.copies.load()),
    @"destroys" : @(state.destroys.load()),
    @"invokes" : @(state.invokes.load()),
    @"final_live" : @(state.live.load()),
    @"events" : events,
    @"source_thread_exited_and_stack_inaccessible_through_callback_and_disposal" :
        @YES,
    @"original_WMF_source_or_ABI_or_permission_or_lifetime_qualified" : @NO
  };
  if (state.queue)
    dispatch_release(state.queue);
  dispatch_release(state.fired);
  dispatch_release(state.disposed);
  dispatch_release(state.cancelled);
  emit(result);
  return result;
}

static NSDictionary *providersBeforeCases() {
  struct Provider {
    const char *name;
    const char *path;
    const char *symbol;
    const char *uuid;
  };
  const Provider providers[] = {
      {"dispatch", "/usr/lib/system/libdispatch.dylib",
       "dispatch_source_set_event_handler",
       "42B50931-38D5-3A5D-90EF-0FD7239C408D"},
      {"Blocks", "/usr/lib/system/libsystem_blocks.dylib", "_Block_copy",
       "A5FDF1FF-B793-3574-8903-D24571EACD25"},
      {"compiler_rt", "/usr/lib/system/libcompiler_rt.dylib",
       "__gcc_personality_v0", "5539B26B-6FA7-341F-9C21-25F04BC8138B"},
      {"unwind", "/usr/lib/system/libunwind.dylib", "_Unwind_Resume",
       "C4187425-764F-3506-A411-5102B50AE804"}};
  NSMutableArray *records = [NSMutableArray array];
  for (const Provider &provider : providers) {
    void *handle = dlopen(provider.path, RTLD_NOW | RTLD_LOCAL);
    require(handle != nullptr, "candidate provider dlopen");
    // Keep each handle for this process's entire fixture lifetime. Symbol
    // addresses are inspected, never cast to callable function pointers.
    void *address = dlsym(handle, provider.symbol);
    Dl_info info;
    require(address && dladdr(address, &info) && info.dli_fbase,
            "actual provider symbol owner");
    NSDictionary *image = imageInfo(
        static_cast<const mach_header *>(info.dli_fbase), info.dli_fname);
    require([image[@"uuid"] isEqualToString:@(provider.uuid)],
            "exact current loaded provider UUID");
    NSArray *versions = image[@"build_versions"];
    require(versions.count > 0, "loaded provider platform records");
    for (NSDictionary *version in versions)
      require([version[@"platform"] unsignedIntValue] == 7,
              "actual loaded platform7");
    [records addObject:@{
      @"name" : @(provider.name),
      @"symbol" : @(provider.symbol),
      @"image" : image
    }];
  }
  NSDictionary *result = @{
    @"type" : @"actual_loaded_provider_prerequisite",
    @"providers" : records,
    @"probe_image" :
        imageInfo(_dyld_get_image_header(0), _dyld_get_image_name(0)),
    @"original_provider_match_or_source_permission_qualified" : @NO
  };
  emit(result);
  return result;
}

int main() {
  @autoreleasepool {
    NSDictionary *providers = providersBeforeCases();
    NSMutableArray *cases = [NSMutableArray array];
    for (const char *mode : {"direct_copy", "dispatch_source"})
      for (size_t payload : {size_t(0), size_t(24), size_t(72)})
        [cases addObject:runCase(mode, payload)];
    emit(@{
      @"type" : @"complete_authored_domain",
      @"cases" : cases,
      @"case_count" : @(cases.count),
      @"provider_prerequisite" : providers,
      @"original_application_or_generated_C_executed" : @NO,
      @"finite_authored_observation_only_not_universal_footprint_or_lifetime_certificate" :
          @YES,
      @"original_source_ABI_effect_permission_or_method_increment" : @NO
    });
    return 0;
  }
}
