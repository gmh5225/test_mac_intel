#include <capstone/capstone.h>
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

extern "C" { unsigned profile_stages[9]; }

int main(int argc, char **argv) {
    if (argc != 6) return 1;
    csh handle = 0;
    if (cs_open(CS_ARCH_X86, std::atoi(argv[1]) == 64 ? CS_MODE_64 : CS_MODE_32, &handle) ||
        cs_option(handle, CS_OPT_TEXT, CS_OPT_OFF)) return 2;
    csh output = 0;
    if (cs_open(CS_ARCH_X86, std::atoi(argv[1]) == 64 ? CS_MODE_64 : CS_MODE_32, &output) ||
        cs_option(output, CS_OPT_DETAIL, CS_OPT_ON)) return 2;
    cs_insn *rendered = cs_malloc(output);
    if (!rendered) return 2;
    cs_insn *insn = cs_malloc(handle);
    if (!insn) return 2;
    std::ifstream file(argv[2], std::ios::binary), spans(argv[3]);
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file), {}};
    std::map<std::string, std::array<uint64_t, 10>> counts;
    std::ofstream records(argv[4], std::ios::binary), differences(argv[5]);
    if (!records || !differences) return 4;
    size_t offset, left;
    uint64_t ip;
    while (spans >> offset >> left >> ip) {
        if (offset > bytes.size() || left > bytes.size() - offset) return 3;
        const auto *cursor = bytes.data()+offset;
        while (left) {
            std::fill_n(profile_stages, 9, 0);
            size_t rendered_left = left;
            uint64_t rendered_pc = ip;
            const uint8_t *rendered_cursor = cursor;
            const auto *begin = cursor;
            const auto initial_ip = ip;
            const size_t initial_left = left;
            bool ok = cs_disasm_iter(handle, &cursor, &left, &ip, insn);
            std::array<unsigned, 7> scan;
            std::copy_n(profile_stages, scan.size(), scan.begin());
            std::fill_n(profile_stages, 9, 0);
            bool formatted = cs_disasm_iter(output, &rendered_cursor, &rendered_left, &rendered_pc, rendered);
            const uint64_t observed[] = {
                static_cast<uint64_t>(begin-bytes.data()), initial_left, initial_ip,
                ok, static_cast<uint64_t>(cursor-begin), left, ip,
                ok ? insn->id : 0u, ok ? static_cast<unsigned>(insn->size) : 0u,
                formatted, static_cast<uint64_t>(rendered_cursor-begin), rendered_left, rendered_pc,
                formatted ? rendered->id : 0u, formatted ? static_cast<unsigned>(rendered->size) : 0u,
            };
            records.write(reinterpret_cast<const char *>(observed),sizeof(observed));
            if (formatted != ok || rendered_left != left || rendered_pc != ip || rendered_cursor != cursor ||
                (ok && (rendered->id != insn->id || rendered->size != insn->size))) {
                static const char hex[] = "0123456789abcdef";
                differences << std::hex << initial_ip << ' ';
                for (size_t i=0;i<std::min<size_t>(initial_left,15);++i)
                    differences << hex[begin[i]>>4] << hex[begin[i]&15];
                differences << std::dec << ' ' << ok << ' ' << observed[7] << ' ' << observed[8]
                            << ' ' << formatted << ' ' << observed[13] << ' ' << observed[14]
                            << ' ' << (ok ? cs_insn_name(handle,insn->id) : "-")
                            << ' ' << (formatted ? rendered->mnemonic : "-") << '\n';
            }
            std::string key;
            if (ok) {
                const char *name = cs_insn_name(handle, insn->id);
                key = name ? name : std::to_string(insn->id);
                unsigned mr = (begin[0]==0x62 && insn->size>=6 && insn->id!=X86_INS_BOUND) ? 5 :
                              (begin[0]==0xc4 && insn->size>=5 && insn->id!=X86_INS_LES) ? 4 :
                              (begin[0]==0xc5 && insn->size>=4 && insn->id!=X86_INS_LDS) ? 3 : 0;
                if (mr) {
                    key += std::string("/") + (mr==5 ? "evex" : mr==4 ? "vex3" : "vex2");
                    key += begin[mr]>=0xc0 ? "/reg" : "/mem";
                }
            } else {
                key = "<invalid>"; ++cursor; --left; ++ip;
            }
            auto &row = counts[key];
            ++row[0];
            for (size_t i=0;i<scan.size();++i) row[i+1]+=scan[i];
            row[8]+=profile_stages[7];row[9]+=profile_stages[8];
        }
    }
    records.close(); differences.close();
    if (!spans.eof() || !records || !differences) return 5;
    for (const auto &[name,row] : counts) {
        std::cout << name;
        for (auto v : row) std::cout << '\t' << v;
        std::cout << '\n';
    }
    cs_free(insn,1); cs_close(&handle); cs_free(rendered,1); cs_close(&output);
}
