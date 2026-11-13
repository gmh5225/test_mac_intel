#include <mach/arm/thread_status.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/ucontext.h>
#include <unistd.h>
#if __has_feature(ptrauth_calls)
#include <ptrauth.h>
#endif
#include <stdio.h>
static volatile sig_atomic_t stage;
extern int caller(void);
extern uintptr_t control_pc(void);
extern uintptr_t captured_lr;
static void catch_signal(int signo, siginfo_t *info, void *ptr) {
  (void)info;
  ucontext_t *uc = ptr;
  arm_thread_state64_t *s = &uc->uc_mcontext->__ss;
  if (signo != SIGTRAP || !uc->uc_mcontext || uc->uc_mcsize != sizeof(*uc->uc_mcontext)) _exit(14);
  uintptr_t pc = control_pc(), lr = arm_thread_state64_get_lr(*s), sp = arm_thread_state64_get_sp(*s);
  if (lr != captured_lr || !pc || !sp) _exit(15);
#if __has_feature(ptrauth_calls)
  void *target = ptrauth_sign_unauthenticated((void *)pc, ptrauth_key_function_pointer, 0);
#else
  void *target = (void *)pc;
#endif
  arm_thread_state64_set_pc_fptr(*s, target);
  arm_thread_state64_set_lr_fptr(*s, target);
  arm_thread_state64_set_sp(*s, sp + 16);
  uc->uc_mcontext->__ns.__v[8] = ((__uint128_t)0x7722 << 64) | 0x3311;
  s->__x[0] = 37;
  stage = 1;
}
int main(void) {
  struct sigaction s = {.sa_sigaction=catch_signal,.sa_flags=SA_SIGINFO};
  sigemptyset(&s.sa_mask);
  if (sigaction(SIGTRAP,&s,0)) return 10;
  int got = caller();
  sigset_t mask; sigprocmask(SIG_SETMASK,0,&mask);
  printf("caller=%d signals=%d masked=%d\n",got,(int)stage,sigismember(&mask,SIGTRAP));
  return stage!=1 || got!=37 || sigismember(&mask,SIGTRAP);
}
