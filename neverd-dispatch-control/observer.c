
#include "neverd/runtime/DarwinArm64eSystemUnwind.h"
#include <dlfcn.h>
#include <execinfo.h>
#include <libunwind.h>
#include <inttypes.h>
#include <mach/arm/thread_status.h>
#include <ptrauth.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ucontext.h>
#include <unistd.h>

enum { stages_count = 5, frame_bytes = 16 };
struct handshake {
  _Atomic int ready;
  _Atomic int done;
};
struct sample {
  uintptr_t pc;
  uintptr_t cfa_offset;
  int is_signed;
  int stack_matches;
};
typedef void (*entry)(struct handshake *);
extern void call_outer(entry, struct handshake *);
extern uintptr_t outer_return_address(void);
extern uintptr_t return_address(void);
_Atomic uintptr_t stage_entry_sp, incoming_x19;
static struct handshake state;
static struct sample samples[stages_count];
static pthread_t worker;
static int entry_only, raw_entry, compact_entry, visits_entry, exact_entry, raw_sp;
static unsigned lookup_offset;
static uintptr_t expected_return, expected_outer, owner, stack_low, stack_high;
struct stack_rule {
  uintptr_t offset, depth;
  unsigned saved_lr, signed_lr, saved_x19;
};
static struct stack_rule *rules;
static size_t rule_count;

// The test host writes the selected image's decoded FDE before execution.
static int read_rules(const char *path) {
  FILE *file = fopen(path, "r");
  if (!file)
    return 0;
  if (fscanf(file, "%zu", &rule_count) != 1 || !rule_count ||
      !(rules = calloc(rule_count, sizeof(*rules)))) {
    fclose(file);
    return 0;
  }
  for (size_t i = 0; i < rule_count; ++i) {
    struct stack_rule *r = &rules[i];
    if (fscanf(file, "%" SCNuPTR " %" SCNuPTR " %u %u %u", &r->offset,
               &r->depth, &r->saved_lr, &r->signed_lr, &r->saved_x19) != 5) {
      fclose(file);
      return 0;
    }
  }
  return fclose(file) == 0;
}

static int at_signal_trampoline(unw_cursor_t *cursor) {
  unw_context_t context;
  if (unw_getcontext(&context) || unw_init_local(cursor, &context))
    return 0;
  for (;;) {
    unw_word_t ip;
    if (unw_get_reg(cursor, UNW_REG_IP, &ip))
      return 0;
    const void *address = ptrauth_strip((void *)ip, ptrauth_key_return_address);
    Dl_info symbol;
    if (dladdr(address, &symbol) && symbol.dli_sname &&
        !strcmp(symbol.dli_sname, "_sigtramp"))
      return 1;
    if (unw_step(cursor) <= 0)
      return 0;
  }
}

static uintptr_t raw_pc(unw_cursor_t *cursor) {
  unw_word_t value;
  if (unw_get_reg(cursor, UNW_REG_IP, &value))
    _exit(30);
  return (uintptr_t)ptrauth_strip((void *)value, ptrauth_key_return_address);
}

static int check_raw_caller(unw_cursor_t *cursor, uintptr_t sp) {
  unw_word_t saved_sp, saved_x19;
  if (raw_pc(cursor) != expected_return ||
      unw_get_reg(cursor, UNW_REG_SP, &saved_sp) ||
      unw_get_reg(cursor, UNW_ARM64_X19, &saved_x19) ||
      saved_x19 != atomic_load(&incoming_x19))
    _exit(31);
  if (unw_step(cursor) <= 0 || raw_pc(cursor) != expected_outer)
    _exit(32);
  return saved_sp == sp;
}

// Both walks use Darwin libunwind and the loaded image's registered tables.
// The first starts in the handler. The second starts at the exact interrupted
// PC, independently of whether this system exposes it when leaving _sigtramp.
static void raw_entry_walk(const ucontext_t *uc) {
  const arm_thread_state64_t *regs = &uc->uc_mcontext->__ss;
  unw_cursor_t cursor;
  const uintptr_t sp = arm_thread_state64_get_sp(*regs);
  if (sp != atomic_load(&stage_entry_sp) || !at_signal_trampoline(&cursor) ||
      unw_step(&cursor) <= 0)
    _exit(33);
  if (raw_pc(&cursor) == owner) {
    visits_entry = 1;
    if (unw_step(&cursor) <= 0)
      _exit(34);
  }
  raw_sp = check_raw_caller(&cursor, sp);

  const uint32_t mode = compact_entry ? UNWIND_ARM64_MODE_FRAMELESS : UNWIND_ARM64_MODE_DWARF;
  const uint32_t other = compact_entry ? UNWIND_ARM64_MODE_DWARF : UNWIND_ARM64_MODE_FRAMELESS;
  if (arm_thread_state64_get_lr(*regs) != expected_return ||
      ndDarwinArm64eInitTableEntryCursor(&cursor, uc, owner, other, &lookup_offset) ||
      ndDarwinArm64eInitIndexedEntryCursor(&cursor, uc, owner + NDArm64eInstructionAlignment, &lookup_offset) ||
      !ndDarwinArm64eInitTableEntryCursor(&cursor, uc, owner, mode, &lookup_offset) ||
      raw_pc(&cursor) != owner + lookup_offset)
    _exit(35);
  for (unsigned i = 0; i < NDArm64ePreservedDCount; ++i) {
    unw_fpreg_t value;
    if (unw_get_fpreg(&cursor, UNW_ARM64_D8 + i, &value) ||
        memcmp(&value, &uc->uc_mcontext->__ns.__v[NDArm64eFirstPreservedD + i], sizeof(value)))
      _exit(36);
  }
  if (unw_step(&cursor) <= 0 || !check_raw_caller(&cursor, sp))
    _exit(37);
  exact_entry = 1;
}

static void observe(int signal, siginfo_t *info, void *context) {
  const ucontext_t *uc = context;
  const arm_thread_state64_t *regs = &uc->uc_mcontext->__ss;
  const uintptr_t pc = arm_thread_state64_get_pc(*regs);
  if (entry_only && (pc != owner || atomic_load(&state.done)))
    return;
  if (raw_entry) {
    if (signal != SIGUSR1)
      _exit(38);
    raw_entry_walk(uc);
    atomic_store(&state.done, 1);
    return;
  }
  const int stage = entry_only ? 1 : atomic_load(&state.ready);
  if (stage < 1 || stage > stages_count || signal != SIGUSR1)
    _exit(10);
  const uintptr_t sp = arm_thread_state64_get_sp(*regs);
  struct sample *s = &samples[stage - 1];
  s->pc = pc;
  if (s->pc < owner)
    _exit(8);
  const uintptr_t offset = s->pc - owner;
  const struct stack_rule *rule = rules;
  for (size_t i = 1; i < rule_count && rules[i].offset <= offset; ++i)
    rule = &rules[i];
  const uintptr_t cfa = sp + rule->depth;
  const uintptr_t entry_sp = atomic_load_explicit(&stage_entry_sp,
                                                   memory_order_acquire);
  if (cfa != entry_sp)
    _exit(12);
  s->cfa_offset = entry_sp - sp;
  const uintptr_t live_lr = arm_thread_state64_get_lr(*regs);
  uintptr_t caller = live_lr;
  if (rule->saved_lr) {
    caller = *(const uintptr_t *)(cfa - sizeof(uintptr_t));
    s->stack_matches = caller == live_lr;
  }
  // The caller selected a modifier for which the hardware signature changes
  // the pointer bits. Authenticate the measured value before using it.
  uintptr_t stripped = (uintptr_t)ptrauth_strip((void *)caller,
                                                ptrauth_key_return_address);
  s->is_signed = caller != stripped;
  if (s->is_signed)
    __asm__ volatile("autib %0, %1" : "+r"(caller) : "r"(cfa));
  if (caller != expected_return)
    _exit(14);

  // The interrupted function preserves FP. The assembly caller's frame
  // records its own LR at CFA-8 and signs it with its entry SP.
  const uintptr_t parent_cfa = arm_thread_state64_get_fp(*regs) + frame_bytes;
  const uintptr_t parent_raw =
      *(const uintptr_t *)(parent_cfa - sizeof(uintptr_t));
  uintptr_t parent = parent_raw;
  __asm__ volatile("autib %0, %1" : "+r"(parent) : "r"(parent_cfa));
  if (parent_raw == parent || parent != expected_outer)
    _exit(15);
  unw_cursor_t system;
  if (!at_signal_trampoline(&system))
    _exit(16);
  NDDarwinArm64eCursor cursor = ndDarwinArm64eSignalCursor(uc);
  if (cursor.PC != s->pc || cursor.SP != sp)
    _exit(17);
  NDDarwinArm64eUnwindRow interrupted = {
      .CFAOffset = rule->depth, .SavedLR = rule->saved_lr,
      .LROffset = -(ptrdiff_t)sizeof(uintptr_t),
      .Signing = rule->signed_lr ? NDArm64eSignedIBWithCFA : NDArm64eUnsigned};
  if (!ndDarwinArm64eStepFrame(&cursor, interrupted, stack_low, stack_high) ||
      cursor.PC != expected_return || cursor.SP != cfa)
    _exit(18);
  const NDDarwinArm64eSavedGPR saved = {NDArm64eFirstPreservedGPR, -frame_bytes};
  if (rule->saved_x19) {
    unw_word_t before, after;
    const NDDarwinArm64eSavedGPR duplicate[] = {saved, saved};
    const NDDarwinArm64eSavedGPR outside = {NDArm64eFirstPreservedGPR, PTRDIFF_MAX};
    if (unw_get_reg(&system, UNW_REG_IP, &before) ||
        ndDarwinArm64eCrossSignalTrampoline(&system, uc, interrupted, duplicate, 2,
                                            stack_low, stack_high, false) ||
        ndDarwinArm64eCrossSignalTrampoline(&system, uc, interrupted, &outside, 1,
                                            stack_low, stack_high, false) ||
        unw_get_reg(&system, UNW_REG_IP, &after) || before != after)
      _exit(26);
  }
  if (!ndDarwinArm64eCrossSignalTrampoline(&system, uc, interrupted, &saved, rule->saved_x19,
                                     stack_low, stack_high, false))
    _exit(23);
  unw_word_t system_pc, preserved;
  if (unw_get_reg(&system, UNW_ARM64_X19, &preserved) ||
      preserved != atomic_load_explicit(&incoming_x19, memory_order_acquire))
    _exit(25);
  if (unw_get_reg(&system, UNW_REG_IP, &system_pc) ||
      (uintptr_t)ptrauth_strip((void *)system_pc, ptrauth_key_return_address) != expected_return ||
      unw_step(&system) <= 0 || unw_get_reg(&system, UNW_REG_IP, &system_pc) ||
      (uintptr_t)ptrauth_strip((void *)system_pc, ptrauth_key_return_address) != expected_outer)
    _exit(24);
  void *frames[2];
  const int count = backtrace_from_fp((void *)cursor.FP, frames, 2);
  const NDDarwinArm64eUnwindRow framed = {
      .CFAFromFP = true, .CFAOffset = frame_bytes, .SavedFP = true,
      .SavedLR = true, .FPOffset = -frame_bytes,
      .LROffset = -(ptrdiff_t)sizeof(uintptr_t),
      .Signing = NDArm64eSignedIBWithCFA};
  // The fixture independently proved the parent has a nonzero IB signature.
  // Replacing it with its canonical address must leave the cursor untouched.
  NDDarwinArm64eCursor forged = cursor;
  forged.LR = expected_outer;
  const NDDarwinArm64eCursor before = forged;
  NDDarwinArm64eUnwindRow live = framed;
  live.SavedLR = false;
  if (ndDarwinArm64eStepFrame(&forged, live, stack_low, stack_high) ||
      memcmp(&before, &forged, sizeof(before)))
    _exit(20);
  live.Signing = NDArm64eSigningUnknown;
  if (ndDarwinArm64eStepFrame(&forged, live, stack_low, stack_high) ||
      ndDarwinArm64eStepFrame(&forged, framed, stack_low, parent_cfa - 1))
    _exit(21);
  live.Signing = NDArm64eSignedIAWithCFA;
  forged.LR = (uintptr_t)ptrauth_sign_unauthenticated(
      (void *)expected_outer, ptrauth_key_asia, parent_cfa);
  if (!ndDarwinArm64eStepFrame(&forged, live, stack_low, stack_high) ||
      forged.PC != expected_outer)
    _exit(22);
  if (!ndDarwinArm64eStepFrame(&cursor, framed, stack_low, stack_high) ||
      cursor.PC != expected_outer || cursor.SP != parent_cfa || count <= 0 ||
      (uintptr_t)ptrauth_strip(frames[0], ptrauth_key_function_pointer) != cursor.PC)
    _exit(19);
  atomic_store(&state.done, stage);
}

static void *interrupt_worker(void *arg) {
  if (entry_only) {
    while (!atomic_load(&state.done)) {
      if (pthread_kill(worker, SIGUSR1))
        _exit(13);
      usleep(100);
    }
    return NULL;
  }
  for (int stage = 1; stage <= stages_count; ++stage) {
    while (atomic_load(&state.ready) != stage)
      sched_yield();
    if (pthread_kill(worker, SIGUSR1))
      _exit(13);
  }
  return NULL;
}

int main(int argc, char **argv) {
  compact_entry = argc == 7 && !strcmp(argv[6], "raw-compact-entry");
  raw_entry = compact_entry || (argc == 7 && !strcmp(argv[6], "raw-entry"));
  entry_only = raw_entry || (argc == 7 && !strcmp(argv[6], "entry"));
  if ((!entry_only && argc != 6) || (!raw_entry && !read_rules(argv[5])))
    return 1;
  alarm(20);
  void *image = dlopen(argv[1], RTLD_NOW | RTLD_LOCAL);
  if (!image)
    return 2;
  entry run = (entry)dlsym(image, compact_entry ? "companion" : "stages");
  if (!run)
    return 3;
  const uintptr_t public_entry = (uintptr_t)ptrauth_strip(
      run, ptrauth_key_function_pointer);
  typedef unsigned (*companion_fn)(void);
  companion_fn companion = (companion_fn)dlsym(image, "companion");
  if (!companion || companion() != strtoul(argv[3], NULL, 10))
    return 9;
  owner = public_entry + strtoull(argv[2], NULL, 10);
  worker = pthread_self();
  stack_high = (uintptr_t)pthread_get_stackaddr_np(worker);
  stack_low = stack_high - pthread_get_stacksize_np(worker);
  expected_return = return_address();
  expected_outer = outer_return_address();
  struct sigaction action = {.sa_sigaction = observe, .sa_flags = SA_SIGINFO};
  sigemptyset(&action.sa_mask);
  if (sigaction(SIGUSR1, &action, NULL))
    return 4;
  pthread_t monitor;
  if (pthread_create(&monitor, NULL, interrupt_worker, NULL))
    return 5;
  if (entry_only) {
    while (!atomic_load(&state.done))
      call_outer(run, NULL);
  } else {
    call_outer(run, &state);
  }
  if (pthread_join(monitor, NULL))
    return 6;
  FILE *out = fopen(argv[4], "w");
  if (!out)
    return 7;
  if (raw_entry) {
    fprintf(out, "%d %d %d %u\n", visits_entry, exact_entry, raw_sp, lookup_offset);
    return fclose(out) || dlclose(image);
  }
  for (int i = 0; i < (entry_only ? 1 : stages_count); ++i) {
    if (samples[i].pc < owner)
      return 8;
    fprintf(out, "%" PRIuPTR " %d %" PRIuPTR " %d\n",
            samples[i].pc - owner, samples[i].is_signed,
            samples[i].cfa_offset, samples[i].stack_matches);
  }
  free(rules);
  return fclose(out) || dlclose(image);
}
