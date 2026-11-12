#include <capstone/capstone.h>

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <stdexcept>
#include <vector>

int main(int argc, char **argv)
{
    try {
        if (argc != 3)
            throw std::runtime_error("expected BITS INPUT");
        const unsigned bits = std::strtoul(argv[1], nullptr, 10);
        if (bits != 16 && bits != 32 && bits != 64)
            throw std::runtime_error("invalid bitness");
        std::ifstream file(argv[2], std::ios::binary);
        std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),
                                   std::istreambuf_iterator<char>()};
        if (bytes.empty())
            throw std::runtime_error("empty input");
        const cs_mode mode = bits == 64 ? CS_MODE_64 : bits == 32 ? CS_MODE_32 : CS_MODE_16;
        csh handle = 0;
        if (cs_open(CS_ARCH_X86, mode, &handle) != CS_ERR_OK ||
            cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
            throw std::runtime_error("cannot initialize decoder");
        cs_insn *insn = cs_malloc(handle);
        if (!insn)
            throw std::runtime_error("cannot allocate instruction");
        const uint8_t *cursor = bytes.data();
        size_t remaining = bytes.size();
        uint64_t address = 0x100000;
        uint64_t instructions = 0, rejected = 0;
        uint64_t legacy_memory = 0, legacy_without_memory = 0, full_repair = 0;
        uint64_t eligible_operands = 0;
        while (remaining) {
            if (!cs_disasm_iter(handle, &cursor, &remaining, &address, insn)) {
                ++rejected;
                ++cursor;
                --remaining;
                ++address;
                continue;
            }
            ++instructions;
            const cs_x86 &x86 = insn->detail->x86;
            if ((x86.opcode[0] & 0xe0) == 0xc0 || x86.opcode[0] == 0x62) {
                ++full_repair;
                continue;
            }
            bool memory = false;
            for (unsigned index = 0; index < x86.op_count; ++index) {
                ++eligible_operands;
                if (x86.operands[index].type == X86_OP_MEM) {
                    memory = true;
                    break;
                }
            }
            if (memory)
                ++legacy_memory;
            else
                ++legacy_without_memory;
        }
        cs_free(insn, 1);
        cs_close(&handle);
        std::printf("{\"instructions\":%llu,\"rejected\":%llu,"
                    "\"legacy_memory\":%llu,\"legacy_without_memory\":%llu,"
                    "\"full_repair\":%llu,\"eligible_operands\":%llu}\n",
                    static_cast<unsigned long long>(instructions),
                    static_cast<unsigned long long>(rejected),
                    static_cast<unsigned long long>(legacy_memory),
                    static_cast<unsigned long long>(legacy_without_memory),
                    static_cast<unsigned long long>(full_repair),
                    static_cast<unsigned long long>(eligible_operands));
        return 0;
    } catch (const std::exception &error) {
        std::fprintf(stderr, "%s\n", error.what());
        return 1;
    }
}
