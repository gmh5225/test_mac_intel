
#include "neverd/runtime/DarwinArm64eSystemUnwind.h"
#include <dlfcn.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

enum { vector_count = 32, profile_count = 4, returned = 73 };
struct vectors {
  __uint128_t v[vector_count];
  uint32_t fpcr, fpsr;
};
struct plan {
  uintptr_t begin, end;
  NDDarwinArm64eUnwindRow row;
  NDDarwinArm64eSavedGPR x19;
  NDDarwinArm64eVectorSaves vectors;
};
typedef void (*frame)(atomic_int *);
extern int invoke_resume(frame, atomic_int *, const struct vectors *,
                         struct vectors *);
static struct plan plan;
static struct vectors input, observed;
static atomic_int ready;
static pthread_t worker;
static uintptr_t low, high, alternate_start, alternate_end;
static volatile sig_atomic_t profile, handled;
static uint32_t saved_fpcr, saved_fpsr;
static unsigned tag;

static int read_plan(const char *name, uintptr_t owner) {
  FILE *f = fopen(name, "r");
  if (!f) return 0;
  unsigned l, h;
  int ok = fscanf(f, "%" SCNuPTR " %" SCNuPTR " %td %td %td %u %u",
                  &plan.begin, &plan.end, &plan.row.CFAOffset,
                  &plan.row.LROffset, &plan.x19.CFAOffset, &l, &h) == 7;
  plan.row.Signing = NDArm64eSignedIBWithCFA;
  plan.row.SavedLR = true;
  plan.x19.Register = NDArm64eFirstPreservedGPR;
  plan.vectors.Complete = true;
  plan.vectors.LowMask = l;
  plan.vectors.HighMask = h;
  for (unsigned d=0; d<NDArm64ePreservedDCount && ok; ++d)
    ok = fscanf(f, "%td %td", &plan.vectors.LowOffsets[d],
                &plan.vectors.HighOffsets[d]) == 2;
  plan.begin += owner;
  plan.end += owner;
  return !fclose(f) && ok;
}

static void observe(int signo, siginfo_t *info, void *data) {
  (void)info;
  ucontext_t *uc = data;
  arm_thread_state64_t *ss = &uc->uc_mcontext->__ss;
  uintptr_t pc = arm_thread_state64_get_pc(*ss), here = (uintptr_t)&data;
  if (signo != SIGUSR1 || atomic_load_explicit(&ready,memory_order_acquire) != (int)tag ||
      pc < plan.begin || pc >= plan.end ||
      (here >= alternate_start && here < alternate_end) != (profile >= 2))
    _exit(10);
  struct __darwin_mcontext64 before = *uc->uc_mcontext;
  NDDarwinArm64eVectorSaves bad = plan.vectors;
  bad.HighOffsets[3] = PTRDIFF_MAX;
  if (ndDarwinArm64eResumeSignalCaller(uc,plan.row,&plan.x19,1,&bad,low,high,false) ||
      memcmp(&before, uc->uc_mcontext,sizeof(before))) _exit(11);
  bad = plan.vectors;
  bad.Complete = false;
  if (ndDarwinArm64eResumeSignalCaller(uc,plan.row,&plan.x19,1,&bad,low,high,false) ||
      memcmp(&before, uc->uc_mcontext,sizeof(before))) _exit(12);
  NDDarwinArm64eUnwindRow wrong = plan.row;
  wrong.Signing = NDArm64eSigningUnknown;
  if (ndDarwinArm64eResumeSignalCaller(uc,wrong,&plan.x19,1,&plan.vectors,low,high,false) ||
      memcmp(&before, uc->uc_mcontext,sizeof(before))) _exit(13);
  saved_fpcr = before.__ns.__fpcr;
  saved_fpsr = before.__ns.__fpsr;
  if (!ndDarwinArm64eResumeSignalCaller(uc,plan.row,&plan.x19,1,&plan.vectors,
                                        low,high,false)) _exit(14);
  ss->__x[0] = returned + profile;
  handled = 1;
}
static void *deliver(void *unused) {
  (void)unused;
  while (!atomic_load_explicit(&ready,memory_order_acquire)) sched_yield();
  if (pthread_kill(worker,SIGUSR1)) _exit(15);
  return 0;
}

int main(int argc, char **argv) {
  if (argc != 5) return 1;
  alarm(30);
  void *image = dlopen(argv[1], RTLD_NOW|RTLD_LOCAL);
  if (!image) return 2;
  frame run = (frame)dlsym(image,"resume_frame");
  tag = (unsigned)strtoul(argv[3],0,10);
  if (!run || !read_plan(argv[4],(uintptr_t)ptrauth_strip(run,ptrauth_key_function_pointer) +
                                 strtoull(argv[2],0,10))) return 3;
  worker = pthread_self();
  high = (uintptr_t)pthread_get_stackaddr_np(worker);
  low = high - pthread_get_stacksize_np(worker);
  stack_t alt = {.ss_size = SIGSTKSZ};
  alt.ss_sp = malloc(alt.ss_size);
  if (!alt.ss_sp || sigaltstack(&alt,0)) return 4;
  alternate_start = (uintptr_t)alt.ss_sp;
  alternate_end = alternate_start + alt.ss_size;
  struct sigaction action = {.sa_sigaction=observe};
  sigemptyset(&action.sa_mask);
  sigset_t beforemask, aftermask;
  if (pthread_sigmask(SIG_SETMASK, 0, &beforemask)) return 5;
  for (profile = 0; profile < profile_count; ++profile) {
    if (profile & 1) sigaddset(&beforemask,SIGUSR2);
    else sigdelset(&beforemask,SIGUSR2);
    if (pthread_sigmask(SIG_SETMASK,&beforemask,0)) return 5;
    action.sa_flags = SA_SIGINFO | (profile >= 2 ? SA_ONSTACK : 0);
    if (sigaction(SIGUSR1,&action,0)) return 6;
    for (unsigned r=0; r<vector_count; ++r)
      input.v[r] = ((__uint128_t)(0xd1d2e3e481828384ULL + r + profile) << 64) |
                   (0xa9bacbdc01020304ULL + r + profile);
    atomic_store(&ready,0);
    handled = 0;
    pthread_t monitor;
    if (pthread_create(&monitor,0,deliver,0)) return 7;
    int result = invoke_resume(run,&ready,&input,&observed);
    if (pthread_join(monitor,0) || !handled || result != returned + profile ||
        pthread_sigmask(SIG_SETMASK,0,&aftermask) || beforemask != aftermask ||
        sigaltstack(0,&alt) || (alt.ss_flags & SS_ONSTACK)) return 8;
    for (unsigned r=0; r<vector_count; ++r) {
      __uint128_t expected = input.v[r];
      if (r >= 12 && r <= 15)
        expected = ((__uint128_t)((0x20 + r) * UINT64_C(0x0101010101010101)) << 64) |
                   (uint64_t)expected;
      if (observed.v[r] != expected) return 16 + r;
    }
    if (saved_fpcr != observed.fpcr || saved_fpsr != observed.fpsr) return 9;
  }
  return dlclose(image);
}
