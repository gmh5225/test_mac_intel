#include <stdlib.h>

extern int __real_main(int, char **);
extern void __llvm_profile_set_filename(const char *);
extern int __llvm_profile_dump(void);

int __wrap_main(int argc, char **argv)
{
    const char *path = getenv("ICED_TRAINING_PROFILE");
    if (!path || !*path)
        return 81;
    __llvm_profile_set_filename(path);
    int result = __real_main(argc, argv);
    if (result)
        return result;
    return __llvm_profile_dump() == 0 ? 0 : 82;
}
