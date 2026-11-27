#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>

static uint64_t register_calls;
static uint64_t other_calls;
extern "C" int __real_vsnprintf(char *, size_t, const char *, va_list);
extern "C" int __wrap_vsnprintf(char *dst, size_t capacity, const char *fmt, va_list args) {
    if (std::strcmp(fmt,"%%%s")==0) ++register_calls;
    else ++other_calls;
    return __real_vsnprintf(dst,capacity,fmt,args);
}
__attribute__((destructor)) static void report() {
    if (const char *path=std::getenv("CAPSTONE_COUNT_FORMATS")) {
        FILE *file=std::fopen(path,"w");
        if (!file) std::abort();
        std::fprintf(file,"%llu %llu\n",(unsigned long long)register_calls,(unsigned long long)other_calls);
        std::fclose(file);
    }
}
