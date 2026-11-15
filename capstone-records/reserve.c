#include <stdlib.h>
#include <unistd.h>

static void *volatile reservation;

__attribute__((constructor)) static void reserve_startup_heap(void)
{
    const char *text = getenv("CAPSTONE_HEAP_SHIFT");
    if (!text)
        return;
    const unsigned long amount = strtoul(text, NULL, 16);
    if (amount > 4096)
        _exit(93);
    if (amount) {
        reservation = malloc(amount);
        if (!reservation)
            _exit(94);
    }
}
