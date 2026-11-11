#include <libunwind.h>
static int target_stage;
static void walk_signal(uintptr_t interrupted) {
  unw_context_t context;
  unw_cursor_t cursor;
  if (unw_getcontext(&context) || unw_init_local(&cursor, &context))
    _exit(40);
  unsigned found = 0;
  for (unsigned i = 0; i != 24; ++i) {
    unw_word_t ip;
    if (unw_get_reg(&cursor, UNW_REG_IP, &ip))
      _exit(41);
    const uintptr_t address = (uintptr_t)ptrauth_strip((void *)ip, ptrauth_key_return_address);
    char mark = address == interrupted ? 'I' : address == expected_return ? 'R' : '.';
    write(2, &mark, 1);
    if (found) {
      if (address != expected_return)
        _exit(42);
      return;
    }
    found = address == interrupted;
    if (unw_step(&cursor) <= 0)
      _exit(43);
  }
  _exit(44);
}
