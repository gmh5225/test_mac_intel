#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern int __real_main(int, char **);
extern uint64_t __llvm_profile_get_size_for_buffer(void);
extern int __llvm_profile_write_buffer(char *);

int __wrap_main(int argc, char **argv)
{
    int result = __real_main(argc, argv);
    if (result != 0)
        return result;

    const char *path = getenv("ICED_TRAINING_PROFILE");
    uint64_t size = __llvm_profile_get_size_for_buffer();
    if (!path || size == 0 || size > SIZE_MAX)
        return 81;
    char *buffer = malloc((size_t)size);
    if (!buffer || __llvm_profile_write_buffer(buffer))
        return 82;
    FILE *out = fopen(path, "wb");
    if (!out)
        return 83;
    int complete = fwrite(buffer, 1, (size_t)size, out) == size;
    int closed = fclose(out);
    free(buffer);
    return complete && !closed ? 0 : 84;
}
