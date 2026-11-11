  if (target_stage == -1) {
    uintptr_t sampled_lr = arm_thread_state64_get_lr(*regs);
    if (sampled_lr != raw)
      _exit(50 + stage);
    uintptr_t cfa = sp + (stage == spill_stage ? frame_bytes : 0);
    if (cfa != entry_sp)
      _exit(60 + stage);
    uintptr_t return_pc = stage == spill_stage
                              ? *(const uintptr_t *)(cfa - sizeof(uintptr_t))
                              : sampled_lr;
    if (stage >= 2 && stage <= 4)
      __asm__ volatile("autib %0, %1" : "+r"(return_pc) : "r"(cfa));
    if (return_pc != expected_return)
      _exit(70 + stage);

    uintptr_t caller_fp = arm_thread_state64_get_fp(*regs);
    if (stage == spill_stage && caller_fp == sp)
      caller_fp = *(const uintptr_t *)caller_fp;
    uintptr_t outer_cfa = caller_fp + frame_bytes;
    uintptr_t outer_raw = *(const uintptr_t *)(outer_cfa - sizeof(uintptr_t));
    uintptr_t outer_pc = outer_raw;
    __asm__ volatile("autib %0, %1" : "+r"(outer_pc) : "r"(outer_cfa));
    if (outer_raw == expected_outer || outer_pc != expected_outer)
      _exit(80 + stage);
  }
