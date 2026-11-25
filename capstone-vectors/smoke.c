#include <stdint.h>
#include <stdlib.h>
#include <time.h>
static volatile uint64_t value = 1;
static void work(void)
{
    for (unsigned i = 0; i < 1000000; ++i)
        value = value * 1664525u + 1013904223u;
}
int main(int argc, char **argv)
{
    if (argc != 2) return 1;
    int inside = atoi(argv[1]);
    if (!inside) work();
    clock();
    if (inside) work();
    clock();
    return 0;
}
