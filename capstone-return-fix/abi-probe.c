#include <capstone/capstone.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

int main(void)
{
    static const uint8_t cases[][9] = {
        {0xe9, 0, 0, 0, 0, 0x4b, 0xff, 0xff, 0xff},
        {0xe8, 0, 0, 0, 0, 0x4b, 0xff, 0xff, 0xff},
        {0xb8, 0, 0, 0, 0, 0x4b, 0xff, 0xff, 0xff},
    };
    int failures = 0;
    for (unsigned text = 0; text < 2; ++text)
        for (unsigned detail = 0; detail < 2; ++detail)
            for (unsigned which = 0; which < 3; ++which) {
                csh h = 0;
                if (cs_open(CS_ARCH_X86, CS_MODE_64, &h) ||
                    cs_option(h, CS_OPT_DETAIL, detail ? CS_OPT_ON : CS_OPT_OFF) ||
                    cs_option(h, CS_OPT_TEXT, text ? CS_OPT_ON : CS_OPT_OFF))
                    return 2;
                cs_insn *insn = cs_malloc(h);
                if (!insn)
                    return 3;
                const uint8_t *cursor = cases[which];
                size_t size = sizeof(cases[which]);
                uint64_t address = 0x1000;
                for (unsigned step = 0; step < 2; ++step) {
                    volatile size_t old_size = size;
                    volatile uintptr_t old_cursor = (uintptr_t)cursor;
                    volatile uint64_t old_address = address;
                    bool ok = cs_disasm_iter(h, &cursor, &size, &address, insn);
                    bool bad = step == 0 ?
                        (!ok || insn->size != 5 || size != 4 ||
                         (uintptr_t)cursor != old_cursor + 5 || address != old_address + 5) :
                        (ok || size != old_size || (uintptr_t)cursor != old_cursor || address != old_address);
                    printf("text=%u detail=%u case=%u step=%u ok=%d size=%zu remaining=%zu delta=%" PRIuPTR " address_delta=%" PRIu64 " bad=%d\n",
                           text, detail, which, step, ok, (size_t)insn->size, size,
                           (uintptr_t)cursor - old_cursor, address - old_address, bad);
                    failures += bad;
                    if (bad)
                        break;
                }
                cs_free(insn, 1);
                cs_close(&h);
            }
    return failures ? 77 : 0;
}
