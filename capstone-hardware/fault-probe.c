#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv)
{
    if (argc != 2)
        return 1;
    const int disabled = atoi(argv[1]);
    unsigned cores = 0;
    for (unsigned i = 0; i < 16; ++i) {
        pid_t child = fork();
        if (child == -1)
            return 2;
        if (child == 0) {
            const struct rlimit zero = {0, 0};
            if (setrlimit(RLIMIT_CORE, &zero))
                _exit(3);
            if (disabled && prctl(PR_SET_DUMPABLE, 0L, 0L, 0L, 0L))
                _exit(4);
            raise(SIGSEGV);
            _exit(5);
        }
        int status;
        if (waitpid(child, &status, 0) != child || !WIFSIGNALED(status) ||
            WTERMSIG(status) != SIGSEGV)
            return 6;
        cores += !!WCOREDUMP(status);
    }
    printf("faults=16 dump_disabled=%d core_status=%u\n", disabled, cores);
    return disabled && cores ? 7 : 0;
}
