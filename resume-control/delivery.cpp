
#include "neverd/runtime/DarwinArm64eSystemUnwind.h"
#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <dlfcn.h>
#include <exception>
#include <mach/mach.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>

struct Marker { int value; };
using Tick = void (*)();
using Scope = void (*)(int *, Tick);
static NDDarwinArm64eExceptionSite site;
static NDDarwinArm64eUnwindRow row;
static NDDarwinArm64eVectorSaves vectors;
static NDDarwinArm64eSavedGPR saved[NDArm64ePreservedGPRCount];
static size_t savedCount;
static std::exception_ptr exception;
static uintptr_t low, high, altLow, altHigh;
static pthread_t target;
static bool alternate;
static std::atomic<bool> active, handled;
static_assert(std::atomic<bool>::is_always_lock_free);
static sigset_t beforeMask;
static int trace;

[[noreturn]] static void deliver(void *payload) {
  sigset_t mask;
  stack_t stack{};
  if (payload != &exception || pthread_sigmask(SIG_SETMASK, nullptr, &mask) ||
      mask != beforeMask || sigaltstack(nullptr, &stack) ||
      (stack.ss_flags & SS_ONSTACK)) _exit(10);
  std::rethrow_exception(exception);
}

static void observe(int, siginfo_t *, void *ctx) {
  auto *uc = static_cast<ucontext_t *>(ctx);
  auto pc = arm_thread_state64_get_pc(uc->uc_mcontext->__ss);
  if (!active.load() || pc < site.Begin || pc >= site.End) return;
  auto address = reinterpret_cast<uintptr_t>(&ctx);
  if (alternate != (address >= altLow && address < altHigh)) _exit(11);
  auto bad = site;
  bad.End = bad.Begin;
  auto before = *uc->uc_mcontext;
  if (ndDarwinArm64eDeliverSignalException(uc,bad,row,saved,savedCount,&vectors,
                                          low,high,false,deliver,&exception) ||
      memcmp(&before,uc->uc_mcontext,sizeof(before))) _exit(12);
  if (!ndDarwinArm64eDeliverSignalException(uc,site,row,saved,savedCount,&vectors,
                                           low,high,false,deliver,&exception)) _exit(13);
  active.store(false);
  handled.store(true);
}
static void *interrupt(void *) {
  while (!active.load()) sched_yield();
  while (!handled.load()) {
    if (pthread_kill(target,SIGUSR1)) _exit(14);
    usleep(100);
  }
  return nullptr;
}
struct Outer {
  ~Outer() { trace = trace * 10 + 2; }
};
int main(int argc, char **argv) {
  if (argc != 6) return 1;
  alarm(30);
  auto image = dlopen(argv[1],RTLD_NOW|RTLD_LOCAL);
  if (!image) return 2;
  auto scope = reinterpret_cast<Scope>(dlsym(image,"signal_scope"));
  auto tick = reinterpret_cast<Tick>(dlsym(image,"signal_tick"));
  if (!tick || !scope) return 3;
  auto file = fopen(argv[2],"rb");
  if (!file || fread(&site,sizeof(site),1,file)!=1 || fread(&row,sizeof(row),1,file)!=1 ||
      fread(&vectors,sizeof(vectors),1,file)!=1 ||
      fread(&savedCount,sizeof(savedCount),1,file)!=1 || savedCount>NDArm64ePreservedGPRCount ||
      fread(saved,sizeof(*saved),savedCount,file)!=savedCount || fclose(file)) return 4;
  auto owner = (site.AtProtectedCall ?
      (uintptr_t)ptrauth_strip(scope,ptrauth_key_function_pointer) :
      (uintptr_t)ptrauth_strip(tick,ptrauth_key_function_pointer)) + strtoull(argv[3],nullptr,10);
  site.Begin += owner;
  site.End += owner;
  alternate = atoi(argv[4]) != 0;
  int expected = atoi(argv[5]);
  target = pthread_self();
  high = (uintptr_t)pthread_get_stackaddr_np(target);
  low = high - pthread_get_stacksize_np(target);
  stack_t alt{};
  alt.ss_size = SIGSTKSZ;
  alt.ss_sp = malloc(alt.ss_size);
  if (!alt.ss_sp || sigaltstack(&alt,nullptr)) return 5;
  altLow = (uintptr_t)alt.ss_sp;
  altHigh = altLow + alt.ss_size;
  struct sigaction action{};
  action.sa_sigaction = observe;
  action.sa_flags = SA_SIGINFO | (alternate ? SA_ONSTACK : 0);
  sigemptyset(&action.sa_mask);
  if (sigaction(site.AtProtectedCall ? SIGTRAP : SIGUSR1,&action,nullptr) || pthread_sigmask(SIG_SETMASK,nullptr,&beforeMask)) return 6;
  exception = std::make_exception_ptr(Marker{73});
  pthread_t monitor{};
  if (site.AtProtectedCall) {
    arm_debug_state64_t debug{};
    debug.__bvr[0] = site.Begin;
    // DBGBCR: enable, EL0 match, all four instruction bytes.
    debug.__bcr[0] = (0xfu << 5) | (2u << 1) | 1u;
    auto thread = mach_thread_self();
    auto result = thread_set_state(thread,ARM_DEBUG_STATE64,
        reinterpret_cast<thread_state_t>(&debug),ARM_DEBUG_STATE64_COUNT);
    mach_port_deallocate(mach_task_self(),thread);
    if (result != KERN_SUCCESS) return 7;
  } else if (pthread_create(&monitor,nullptr,interrupt,nullptr)) return 7;
  try {
    Outer outer;
    try {
      active.store(true);
      scope(&trace,tick);
      return 8;
    } catch (const Marker &m) {
      if (trace != expected || m.value != 73 || std::current_exception() != exception) return 15;
      throw;
    }
  } catch (const Marker &m) {
    if (trace != expected*10+2 || m.value != 73 || std::current_exception()!=exception) return 16;
  }
  return (!site.AtProtectedCall && pthread_join(monitor,nullptr)) || !handled.load() || dlclose(image);
}
