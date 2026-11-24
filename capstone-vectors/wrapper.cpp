extern "C" {
struct BenchApi {
  csh handle = 0;
  cs_insn *insn = nullptr;
  unsigned mode = 0;
};
void *bench_create(unsigned bits, unsigned mode) {
  auto *state = new BenchApi;
  state->mode = mode;
  if (cs_open(CS_ARCH_X86, bits == 32 ? CS_MODE_32 : CS_MODE_64, &state->handle) ||
      cs_option(state->handle, CS_OPT_DETAIL, mode == 2 ? CS_OPT_ON : CS_OPT_OFF) ||
      cs_option(state->handle, CS_OPT_TEXT, mode ? CS_OPT_ON : CS_OPT_OFF) ||
      !(state->insn = cs_malloc(state->handle))) std::abort();
  return state;
}
void bench_run(BenchApi *state, const uint8_t *bytes, const Span *spans,
               size_t count, unsigned repeats, Result *output) {
  Result total;
  for (unsigned n = 0; n < repeats; ++n) {
    for (size_t j = 0; j < count; ++j) {
      const auto &f = spans[j];
      auto row = state->mode ?
          cs_span<X86_disasmIterText>(bytes + f.offset, f.size, state->handle,
                                      state->insn, f.ip, state->mode) :
          batch_span<false, X86_scanNativeBatch>(bytes + f.offset, f.size,
                                      state->handle, state->insn, f.ip);
      add_result(total, row, f);
    }
  }
  *output = total;
}
void bench_close(BenchApi *state) {
  cs_free(state->insn, 1);
  cs_close(&state->handle);
  delete state;
}
void bench_qos() { pthread_set_qos_class_self_np(QOS_CLASS_USER_INITIATED, 0); }
void *bench_text_address() { return reinterpret_cast<void *>(&X86_disasmIterText); }
}
