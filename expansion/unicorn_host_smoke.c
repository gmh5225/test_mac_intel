#include <stdint.h>
#include <stdio.h>
#include <unicorn/unicorn.h>

#ifdef TRACE_HOST_FAILURE
#include <windows.h>
static LONG CALLBACK trace_exception(PEXCEPTION_POINTERS exception) {
  unsigned char bytes[16];
  SIZE_T count = 0;
  fprintf(stderr, "EXCEPTION code=%08lx pc=%p fault=%p\n",
          exception->ExceptionRecord->ExceptionCode,
          exception->ExceptionRecord->ExceptionAddress,
          (void *)exception->ExceptionRecord->ExceptionInformation[1]);
  if (ReadProcessMemory(GetCurrentProcess(),
                        exception->ExceptionRecord->ExceptionAddress,
                        bytes, sizeof(bytes), &count)) {
    SIZE_T i;
    fputs("PC BYTES", stderr);
    for (i = 0; i < count; ++i) fprintf(stderr, " %02x", bytes[i]);
    fputc('\n', stderr);
  }
  return EXCEPTION_CONTINUE_SEARCH;
}
#define TRACE(expression) fprintf(stderr, "RUN %d %s\n", __LINE__, #expression)
#else
#define TRACE(expression) ((void)0)
#endif

#define CHECK(expression)                                                      \
  do {                                                                         \
    TRACE(expression);                                                         \
    if (!(expression)) {                                                       \
      fprintf(stderr, "check failed at line %d: %s\n", __LINE__, #expression); \
      return 1;                                                                \
    }                                                                          \
  } while (0)

static const uint64_t base = 0x1000;

static int open_image(uc_engine **engine, const unsigned char *code,
                      size_t size) {
  CHECK(uc_open(UC_ARCH_X86, UC_MODE_64, engine) == UC_ERR_OK);
  CHECK(uc_mem_map(*engine, base, 0x3000, UC_PROT_ALL) == UC_ERR_OK);
  CHECK(uc_mem_write(*engine, base, code, size) == UC_ERR_OK);
  return 0;
}

struct nested_result {
  unsigned calls;
  uc_err error;
};

static void nested_hook(uc_engine *engine, uint64_t address, uint32_t size,
                        void *opaque) {
  struct nested_result *result = (struct nested_result *)opaque;
  (void)size;
  if (address == base + 5 && result->calls == 0) {
    ++result->calls;
    result->error = uc_emu_start(engine, base + 0x1000, base + 0x1002, 0, 1000);
  }
}

int main(void) {
  uc_engine *engine;
  uc_context *saved;
  uint64_t value = 0;
  const unsigned char normal[] = {0xb8, 7, 0, 0, 0};
  const unsigned char invalid[] = {0x0f, 0x0b};
  const unsigned char read_unmapped[] = {0x48, 0xa1, 0, 0, 0, 0, 0, 0, 0, 0};
  const unsigned char outer[] = {0xb8, 5, 0, 0, 0, 0x90, 0x83, 0xc0, 3};

  setvbuf(stdout, NULL, _IONBF, 0);
#ifdef TRACE_HOST_FAILURE
  SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
  AddVectoredExceptionHandler(1, trace_exception);
#endif

  CHECK(open_image(&engine, normal, sizeof(normal)) == 0);
  CHECK(uc_emu_start(engine, base, base + sizeof(normal), 1000000, 1000) ==
        UC_ERR_OK);
  CHECK(uc_reg_read(engine, UC_X86_REG_RAX, &value) == UC_ERR_OK && value == 7);
  puts("PASS normal-execution");
  CHECK(uc_context_alloc(engine, &saved) == UC_ERR_OK);
  CHECK(uc_context_save(engine, saved) == UC_ERR_OK);
  value = 99;
  CHECK(uc_reg_write(engine, UC_X86_REG_RAX, &value) == UC_ERR_OK);
  CHECK(uc_context_restore(engine, saved) == UC_ERR_OK);
  CHECK(uc_reg_read(engine, UC_X86_REG_RAX, &value) == UC_ERR_OK && value == 7);
  CHECK(uc_context_free(saved) == UC_ERR_OK);
  CHECK(uc_close(engine) == UC_ERR_OK);
  puts("PASS context-restore");

  CHECK(open_image(&engine, invalid, sizeof(invalid)) == 0);
  CHECK(uc_emu_start(engine, base, base + sizeof(invalid), 1000000, 1000) ==
        UC_ERR_INSN_INVALID);
  CHECK(uc_close(engine) == UC_ERR_OK);
  puts("PASS invalid-instruction-exit");

  CHECK(open_image(&engine, read_unmapped, sizeof(read_unmapped)) == 0);
  CHECK(uc_emu_start(engine, base, base + sizeof(read_unmapped), 1000000,
                     1000) == UC_ERR_READ_UNMAPPED);
  CHECK(uc_close(engine) == UC_ERR_OK);
  puts("PASS unmapped-read-exit");

  /* Nested calls share one engine timer. Use instruction limits here; the
   * harness also bounds this complete process to 15 seconds. */
  CHECK(open_image(&engine, outer, sizeof(outer)) == 0);
  CHECK(uc_mem_write(engine, base + 0x1000, invalid, sizeof(invalid)) ==
        UC_ERR_OK);
  {
    uc_hook hook;
    struct nested_result nested = {0, UC_ERR_OK};
    CHECK(uc_hook_add(engine, &hook, UC_HOOK_CODE, nested_hook, &nested, 1,
                      0) == UC_ERR_OK);
    CHECK(uc_emu_start(engine, base, base + sizeof(outer), 0, 1000) ==
          UC_ERR_OK);
    CHECK(nested.calls == 1 && nested.error == UC_ERR_INSN_INVALID);
    CHECK(uc_reg_read(engine, UC_X86_REG_RAX, &value) == UC_ERR_OK &&
          value == 8);
    CHECK(uc_hook_del(engine, hook) == UC_ERR_OK);
  }
  CHECK(uc_close(engine) == UC_ERR_OK);
  puts("PASS nested-fault-resume");
  return 0;
}
