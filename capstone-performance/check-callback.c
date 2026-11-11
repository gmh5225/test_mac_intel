#include <capstone/capstone.h>
#include <dlfcn.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef RTLD_FIRST
#define RTLD_FIRST 0
#endif

typedef struct {
    void *library;
    cs_err (*open)(cs_arch, cs_mode, csh *);
    cs_err (*close)(csh *);
    cs_err (*option)(csh, cs_opt_type, uintptr_t);
    cs_insn *(*alloc)(csh);
    void (*release)(cs_insn *, size_t);
    bool (*iter)(csh, const uint8_t **, size_t *, uint64_t *, cs_insn *);
} API;

typedef struct {
    cs_insn instruction;
    cs_detail detail;
    char format[128];
} Snapshot;

typedef struct {
    Snapshot events[16], final;
    unsigned calls, allocation_calls;
    bool decoded, overflow;
    cs_err option_error;
    size_t remaining;
    uint64_t address;
} Result;

static API *active_api;
static Result *active_result;
static cs_insn *active_instruction;
static csh active_handle;
static bool disable_detail;
static bool switch_formatter;

static void capture(Snapshot *snapshot, const char *format)
{
    memcpy(&snapshot->instruction, active_instruction, sizeof(snapshot->instruction));
    snapshot->instruction.detail = NULL;
    memcpy(&snapshot->detail, active_instruction->detail, sizeof(snapshot->detail));
    if (format)
        snprintf(snapshot->format, sizeof(snapshot->format), "%s", format);
}

static int formatter(char *text, size_t size, const char *format, va_list args)
{
    if (active_result) {
        unsigned index = active_result->calls++;
        if (index < sizeof(active_result->events) / sizeof(active_result->events[0]))
            capture(&active_result->events[index], format);
        else
            active_result->overflow = true;
        if (disable_detail)
            active_result->option_error = active_api->option(active_handle, CS_OPT_DETAIL, CS_OPT_OFF);
    }
    cs_opt_mem standard = { malloc, calloc, realloc, free, vsnprintf };
    if (switch_formatter && active_api->option(0, CS_OPT_MEM, (uintptr_t)&standard) != CS_ERR_OK)
        abort();
    memset(text, 0x5a, size);
    int written = vsnprintf(text, size, format, args);
    return written >= 0 && (size_t)written + 2 < size ? written + 2 : written;
}

static void *allocate(size_t size)
{
    if (active_result) ++active_result->allocation_calls;
    return malloc(size);
}
static void *allocate_zero(size_t count, size_t size)
{
    if (active_result) ++active_result->allocation_calls;
    return calloc(count, size);
}
static void *resize(void *pointer, size_t size)
{
    if (active_result) ++active_result->allocation_calls;
    return realloc(pointer, size);
}
static void release(void *pointer)
{
    if (active_result) ++active_result->allocation_calls;
    free(pointer);
}

static bool load(API *api, const char *path)
{
    api->library = dlopen(path, RTLD_NOW | RTLD_LOCAL | RTLD_FIRST);
    if (!api->library) {
        fprintf(stderr, "%s\n", dlerror());
        return false;
    }
#define LOAD(field, name) do { \
    void *symbol = dlsym(api->library, name); \
    if (!symbol || sizeof(symbol) != sizeof(api->field)) return false; \
    memcpy(&api->field, &symbol, sizeof(api->field)); \
} while (0)
    LOAD(open, "cs_open");
    LOAD(close, "cs_close");
    LOAD(option, "cs_option");
    LOAD(alloc, "cs_malloc");
    LOAD(release, "cs_free");
    LOAD(iter, "cs_disasm_iter");
#undef LOAD
    cs_opt_mem memory = { allocate, allocate_zero, resize, release, formatter };
    return api->option(0, CS_OPT_MEM, (uintptr_t)&memory) == CS_ERR_OK;
}

static bool run(API *api, cs_mode mode, uint32_t word, bool disable, bool restore, bool real, Result *result)
{
    uint8_t bytes[4];
    for (unsigned i = 0; i < 4; ++i)
        bytes[i] = (uint8_t)(word >> (8 * ((mode & CS_MODE_BIG_ENDIAN) ? 3 - i : i)));
    csh handle;
    memset(result, 0, sizeof(*result));
    cs_opt_mem custom = { allocate, allocate_zero, resize, release, formatter };
    if (api->option(0, CS_OPT_MEM, (uintptr_t)&custom) != CS_ERR_OK) return false;
    if (api->open(CS_ARCH_PPC, mode, &handle) != CS_ERR_OK) return false;
    if (api->option(handle, CS_OPT_DETAIL, CS_OPT_ON | (real ? CS_OPT_DETAIL_REAL : 0)) != CS_ERR_OK) return false;
    cs_insn *instruction = api->alloc(handle);
    if (!instruction || !instruction->detail) return false;
    cs_detail *saved_detail = instruction->detail;
    memset(instruction, 0, sizeof(*instruction));
    instruction->detail = saved_detail;
    memset(instruction->detail, 0xa5, sizeof(*instruction->detail));
    const uint8_t *cursor = bytes;
    result->remaining = sizeof(bytes);
    result->address = 0x1000;
    active_api = api;
    active_instruction = instruction;
    active_handle = handle;
    disable_detail = disable;
    switch_formatter = restore;
    active_result = result;
    result->decoded = api->iter(handle, &cursor, &result->remaining, &result->address, instruction);
    capture(&result->final, NULL);
    active_result = NULL;
    active_instruction = NULL;
    api->release(instruction, 1);
    api->close(&handle);
    return result->decoded && result->calls > 0 && !result->overflow &&
           result->remaining == 0 && result->option_error == CS_ERR_OK;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr, "usage: %s BASE_LIBRARY NEW_LIBRARY\n", argv[0]);
        return 2;
    }
    API base, newer;
    if (!load(&base, argv[1]) || !load(&newer, argv[2])) return 2;
    const cs_mode modes[] = {
        CS_MODE_32, CS_MODE_64,
        CS_MODE_32 | CS_MODE_BIG_ENDIAN, CS_MODE_64 | CS_MODE_BIG_ENDIAN
    };
    /* li, lis, addi, and a conditional branch exercise aliases and fallback. */
    const uint32_t words[] = {0x3860002a, 0x3c60ffff, 0x3863002a, 0x41820010};
    unsigned snapshot_differences = 0, final_differences = 0, scenarios = 0;
    for (unsigned mode = 0; mode < 4; ++mode)
        for (unsigned fixture = 0; fixture < 4; ++fixture)
            for (unsigned disable = 0; disable < 2; ++disable)
                for (unsigned restore = 0; restore < 2; ++restore)
                    for (unsigned real = 0; real < 2; ++real) {
                        Result a, b;
                        if (!run(&base, modes[mode], words[fixture], disable, restore, real, &a) ||
                            !run(&newer, modes[mode], words[fixture], disable, restore, real, &b)) {
                            fprintf(stderr, "callback scenario failed mode=%u word=%08x disable=%u restore=%u real=%u\n",
                                    modes[mode], words[fixture], disable, restore, real);
                            return 2;
                        }
                        bool same_events = a.calls == b.calls && a.allocation_calls == b.allocation_calls &&
                            memcmp(a.events, b.events, sizeof(a.events)) == 0;
                        bool same_final = memcmp(&a.final, &b.final, sizeof(a.final)) == 0 &&
                            a.remaining == b.remaining && a.address == b.address && a.option_error == b.option_error;
                        snapshot_differences += !same_events;
                        final_differences += !same_final;
                        ++scenarios;
                        printf("mode=%u word=%08x disable=%u restore=%u real=%u events=%u final=%u calls=%u/%u alias_at_callback=%" PRIu64 "/%" PRIu64 " final_alias=%" PRIu64 "/%" PRIu64 "\n",
                               modes[mode], words[fixture], disable, restore, real, same_events, same_final,
                               a.calls, b.calls, a.events[0].instruction.alias_id, b.events[0].instruction.alias_id,
                               a.final.instruction.alias_id, b.final.instruction.alias_id);
                    }
    printf("scenarios=%u snapshot_differences=%u final_differences=%u\n", scenarios, snapshot_differences, final_differences);
    return snapshot_differences || final_differences ? 1 : 0;
}
