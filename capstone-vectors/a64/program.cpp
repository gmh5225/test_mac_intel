#include <capstone/capstone.h>
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <vector>

static uint64_t nanoseconds(clockid_t which) {
    timespec ts{};
    if (clock_gettime(which, &ts)) std::abort();
    return uint64_t(ts.tv_sec) * 1000000000 + ts.tv_nsec;
}
struct Counts {
    uint64_t decoded{}, rejected{}, sum{};
    bool operator==(const Counts &other) const {
        return decoded == other.decoded && rejected == other.rejected && sum == other.sum;
    }
};
static Counts consume(csh handle, cs_insn *record, const std::vector<uint8_t> &bytes, uint64_t address, int mode) {
    const uint8_t *code = bytes.data();
    size_t size = bytes.size();
    Counts result{};
    while (size) {
        if (!cs_disasm_iter(handle, &code, &size, &address, record)) {
            const size_t step = std::min(size, size_t(4));
            ++result.rejected;
            size -= step;
            address += step;
            code += step;
            continue;
        }
        ++result.decoded;
        result.sum += record->id + record->size;
        if (mode) result.sum += std::strlen(record->mnemonic) + std::strlen(record->op_str);
        if (mode == 2) {
            cs_regs read, written;
            uint8_t nr{}, nw{};
            if (cs_regs_access(handle, record, read, &nr, written, &nw) != CS_ERR_OK) std::abort();
            result.sum += record->detail->aarch64.op_count + nr + nw;
            for (unsigned i=0; i<nr; ++i) result.sum += read[i];
            for (unsigned i=0; i<nw; ++i) result.sum += written[i];
        }
    }
    return result;
}
int main(int argc, char **argv) {
    if (argc != 5) return 1;
    std::ifstream file(argv[1], std::ios::binary);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file), {}};
    const uint64_t start = std::strtoull(argv[2], nullptr, 10);
    const int mode = std::atoi(argv[3]), reps = std::atoi(argv[4]);
    if (bytes.empty() || reps < 1 || mode < 0 || mode > 2) return 2;
    csh handle{};
    if (cs_open(CS_ARCH_AARCH64, CS_MODE_LITTLE_ENDIAN, &handle) ||
        cs_option(handle, CS_OPT_TEXT, mode ? CS_OPT_ON : CS_OPT_OFF) ||
        cs_option(handle, CS_OPT_DETAIL, mode == 2 ? CS_OPT_ON : CS_OPT_OFF)) return 3;
    cs_insn *record = cs_malloc(handle);
    if (!record) return 4;
    const Counts expected = consume(handle, record, bytes, start, mode);
    const uint64_t wall = nanoseconds(CLOCK_MONOTONIC), cpu = nanoseconds(CLOCK_PROCESS_CPUTIME_ID);
    for (int i=0; i<reps; ++i) if (!(consume(handle,record,bytes,start,mode) == expected)) return 5;
    const uint64_t elapsed_cpu = nanoseconds(CLOCK_PROCESS_CPUTIME_ID) - cpu;
    const uint64_t elapsed_wall = nanoseconds(CLOCK_MONOTONIC) - wall;
    std::printf("%llu %llu %llu %llu %llu\n", (unsigned long long)elapsed_cpu, (unsigned long long)elapsed_wall,
                (unsigned long long)expected.decoded, (unsigned long long)expected.rejected, (unsigned long long)expected.sum);
    cs_free(record, 1);
    cs_close(&handle);
}
