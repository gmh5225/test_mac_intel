// Test-only switch in the candidate's PPC validator, installed before main().
#define _GNU_SOURCE
#include <errno.h>
#include <inttypes.h>
#include <link.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

static int select_path(struct dl_phdr_info *info, size_t size, void *unused)
{
    if (info->dlpi_name[0] != '\0')
        return 0;
    const char *control = getenv("CAPSTONE_PROBE_ENTRY");
    uintptr_t offset;
    unsigned expected[3], fallback;
    if (!control || sscanf(control, "%" SCNxPTR ":%x:%x:%x:%u", &offset,
                           &expected[0], &expected[1], &expected[2], &fallback) != 5)
        return 0;
    for (size_t i = 0; i < info->dlpi_phnum; ++i) {
        const ElfW(Phdr) *ph = &info->dlpi_phdr[i];
        if (ph->p_type != PT_LOAD || !(ph->p_flags & PF_X) ||
            offset < ph->p_vaddr || offset + 3 > ph->p_vaddr + ph->p_memsz)
            continue;
        unsigned char *entry = (unsigned char *)(info->dlpi_addr + offset);
        unsigned char original[3];
        for (size_t j = 0; j < sizeof(original); ++j) {
            original[j] = entry[j];
            if (original[j] != expected[j])
                return 0;
        }
        const uintptr_t page_size = (uintptr_t)sysconf(_SC_PAGESIZE);
        uintptr_t start = (uintptr_t)entry & ~(page_size - 1);
        size_t span = (uintptr_t)(entry + 3) - start;
        if (mprotect((void *)start, span, PROT_READ | PROT_WRITE))
            return 0;
        const unsigned char return_false[] = { 0x31, 0xc0, 0xc3 };
        memcpy(entry, fallback ? return_false : original, sizeof(original));
        if (mprotect((void *)start, span, PROT_READ | PROT_EXEC))
            return 0;
        return 1;
    }
    return 0;
}

__attribute__((constructor)) static void initialize_control(void)
{
    if (!dl_iterate_phdr(select_path, NULL)) {
        fputs("Could not verify and install the placement diagnostic\n", stderr);
        _exit(125);
    }
}
