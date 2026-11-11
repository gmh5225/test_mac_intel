/* Compiled separately, without LTO. Both adapters expose all produced state
 * to the same external observer while keeping the timed output buffers live. */
void observe_public(const void *instruction, const void *text, const void *reads,
                    const void *writes) {
    __asm__ volatile ("" : : "r"(instruction), "r"(text), "r"(reads), "r"(writes) : "memory");
}
