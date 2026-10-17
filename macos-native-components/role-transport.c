/* Authored execve transport and byte-exact argument/environment control. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
extern char **environ;
static void hex(const char *s) {
    if (!s) { fputs("null", stdout); return; }
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)s; *p; ++p) printf("%02x", *p);
    putchar('"');
}
int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--capture") == 0) {
        fputs("{\"argv0_hex\":", stdout); hex(argv[0]);
        fputs(",\"env_hex\":", stdout); hex(getenv("ARGV0"));
        fputs(",\"args\":[", stdout);
        for (int i = 2; i < argc; ++i) { if (i > 2) putchar(','); hex(argv[i]); }
        puts("]}");
        return 37;
    }
    if (argc == 2 && strcmp(argv[1], "--flood") == 0) {
        for (int i = 0; i < 262145; ++i) putchar('x');
        return 0;
    }
    if (argc < 3) return 64;
    execve(argv[1], argv + 2, environ);
    perror("owned role execve transport");
    return 126;
}
