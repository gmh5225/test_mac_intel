/* Authored dynamic-permission, UTF-8 fragmentation and descendant controls. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
int main(int argc, char **argv) {
    if (argc == 2 && strcmp(argv[1], "--hold-descendant") == 0) {
        pid_t child = fork();
        if (child < 0) return 64;
        if (!child) { sleep(30); _exit(0); }
        printf("{\"child\":%d}\n", child); fflush(stdout); return 0;
    }
    if (argc != 1) return 65;
    puts("{\"type\":\"control_request\",\"request_id\":\"owned-1\",\"request\":{\"subtype\":\"can_use_tool\",\"tool_name\":\"Write\",\"input\":{\"file_path\":\"owned.txt\",\"content\":\"fixture\"}}}");
    fflush(stdout);
    char line[4096];
    if (!fgets(line, sizeof(line), stdin) || !strstr(line, "owned-1") || !strstr(line, "updatedInput")) return 66;
    const char first[] = "{\"type\":\"done\",\"text\":\"\xce";
    const char second[] = "\xb1\"}\n";
    if (write(STDOUT_FILENO, first, sizeof(first)-1) != (ssize_t)sizeof(first)-1) return 67;
    usleep(10000);
    if (write(STDOUT_FILENO, second, sizeof(second)-1) != (ssize_t)sizeof(second)-1) return 68;
    return fgets(line, sizeof(line), stdin) == NULL ? 0 : 69;
}
