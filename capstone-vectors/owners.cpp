#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <map>
#include <string>
#include <tuple>
using Row = std::tuple<uintptr_t, std::string, std::string, std::string>;
static std::map<Row, unsigned> calls;
static unsigned edges;
extern "C" clock_t __real_clock();
extern "C" clock_t __wrap_clock() {
    ++edges;
    return __real_clock();
}
extern "C" void trace_format_owner(void *caller, const char *fmt, va_list source) {
    if (edges != 1) return;
    std::string a, b;
    if (std::strncmp(fmt, "%s", 2) == 0) {
        va_list copy;
        va_copy(copy, source);
        const char *s = va_arg(copy, const char *);
        a = s ? s : "(null)";
        if (std::strncmp(fmt + 2, "%s", 2) == 0) {
            s = va_arg(copy, const char *);
            b = s ? s : "(null)";
        }
        va_end(copy);
    }
    ++calls[{reinterpret_cast<uintptr_t>(caller), fmt, a, b}];
}
static void hex_field(FILE *f, const std::string &s) {
    std::fputc('\t', f);
    constexpr char digits[] = "0123456789abcdef";
    for (unsigned char c : s) { std::fputc(digits[c >> 4], f); std::fputc(digits[c & 15], f); }
}
struct Output {
    ~Output() {
        const char *path = std::getenv("FORMAT_CALLS");
        if (!path) return;
        if (edges != 2) std::abort();
        FILE *f = std::fopen(path, "w");
        if (!f) std::abort();
        for (const auto &[row, count] : calls) {
            const auto &[pc, fmt, a, b] = row;
            std::fprintf(f, "%zx\t%u", static_cast<size_t>(pc), count);
            hex_field(f, fmt); hex_field(f, a); hex_field(f, b); std::fputc('\n', f);
        }
        if (std::fclose(f)) std::abort();
    }
};
static Output output;
