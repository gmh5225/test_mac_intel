/* Authored supervision controls; no recovered program code. */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 64;
    if (!strcmp(argv[1], "--quick-exit")) return 0;
    if (!strcmp(argv[1], "--close-streams-then-exit")) {
        close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
        usleep(150000); return 0;
    }
    if (!strcmp(argv[1], "--child-without-pipes") || !strcmp(argv[1], "--child-holds-pipes")) {
        pid_t child = fork(); if (child < 0) return 65;
        if (!child) {
            if (!strcmp(argv[1], "--child-without-pipes")) {
                close(STDIN_FILENO); close(STDOUT_FILENO); close(STDERR_FILENO);
            }
            sleep(30); return 0;
        }
        printf("{\"authored_child_pid\":%d}\n", (int)child); fflush(stdout);
        return 0;
    }
    return 64;
}
