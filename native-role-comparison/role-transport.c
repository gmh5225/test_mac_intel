/* Authored argument transport. The target receives only this fixed environment. */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--flood-control") == 0) {
        for (int i = 0; i < 262145; ++i) putchar('x');
        return 0;
    }
    if (argc > 1 && strcmp(argv[1], "--transport-control") == 0) {
        for (int i = 0; i < argc; ++i) {
            for (const unsigned char *p = (const unsigned char *)argv[i]; *p; ++p)
                printf("%02x", *p);
            putchar('\n');
        }
        printf("ARGV0=%s\n", getenv("ARGV0") ? getenv("ARGV0") : "<unset>");
#if defined(__linux__)
        FILE *status = fopen("/proc/self/status", "r");
        if (!status) return 65;
        char line[256]; unsigned long long effective = ~0ULL;
        while (fgets(line, sizeof(line), status))
            if (sscanf(line, "CapEff: %llx", &effective) == 1) break;
        fclose(status);
        if (effective != 0 || getuid() == 0 || getpid() != 1 ||
            prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return 66;
#endif
        return 0;
    }
    if (argc == 2 && strcmp(argv[1], "--env-control") == 0) {
        printf("ARGV0=%s\n", getenv("ARGV0") ? getenv("ARGV0") : "<unset>");
        return 0;
    }
    if (argc < 3) return 64;
    const char *canary = getenv("BOUNDARY_OUTSIDE");
    if (!canary || canary[0] != '/') return 67;
    char outside[PATH_MAX + 32];
    if (snprintf(outside, sizeof(outside), "BOUNDARY_OUTSIDE=%s", canary) >= (int)sizeof(outside)) return 68;
    char *environment[] = {"HOME=/home/test", "PATH=/unavailable", "LANG=C.UTF-8",
        "LC_ALL=C.UTF-8", outside, NULL};
    execve(argv[1], argv + 2, environment);
    perror("authored role transport execve");
    return 126;
}
