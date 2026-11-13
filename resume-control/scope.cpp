
namespace {
struct Guard {
  int *trace;
  __attribute__((always_inline)) ~Guard() {
#ifdef NEVERD_RESUME_PUBLISHED
    *trace = *trace * 10 + 3;
#else
    *trace = *trace * 10 + 1;
#endif
  }
};
}
extern "C" __attribute__((noinline)) void signal_tick() {
  asm volatile("");
}
extern "C" __attribute__((noinline)) void signal_scope(int *trace, void (*tick)()) {
  Guard live{trace};
  for (;;) tick();
}
