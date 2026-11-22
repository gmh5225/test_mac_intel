#include "arch/X86/X86ScanAdapter.h"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iterator>
#include <map>
#include <tuple>
#include <vector>

extern "C" uint32_t first_word(int bits, const uint8_t *code, size_t remaining);
int main(int argc, char **argv) {
    if (argc != 4) return 1;
    const int bits = std::atoi(argv[1]);
    std::ifstream in(argv[2], std::ios::binary), spans(argv[3]);
    if (!in || !spans) return 2;
    const std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(in), {}};
    csh h = 0;
    if (cs_open(CS_ARCH_X86, bits == 64 ? CS_MODE_64 : CS_MODE_32, &h) ||
        cs_option(h, CS_OPT_TEXT, CS_OPT_OFF)) return 3;
    using Key = std::tuple<unsigned, unsigned, unsigned, unsigned, unsigned, unsigned>;
    std::map<Key, unsigned> counts;
    size_t pos, size; uint64_t ip;
    while (spans >> pos >> size >> ip) {
        if (pos > bytes.size() || size > bytes.size() - pos) return 4;
        while (size) {
            const auto p = bytes.data() + pos;
            uint32_t reference = 0;
            const auto result = X86_scanBatch(h, p, size, ip, &reference, 1);
            const auto word = first_word(bits, p, size);
            if (word && (!result.count || reference != word)) return 5;
            const unsigned length = result.count ? reference & 255 : 1;
            if (!length || length > size || (result.count && result.bytes != length)) return 6;
            const unsigned byte = p[0];
            unsigned map=0, op=byte, form=0;
            if (byte==0xc4 && length>=4 && (bits==64 || (p[1]&0xc0)==0xc0)) {
                map=p[1]&31; op=p[3]; form=length>=5?1+(p[4]>=0xc0):0;
            } else if (byte==0x62 && length>=6 && (bits==64 || (p[1]&0xc0)==0xc0)) {
                map=p[1]&7; op=p[4]; form=1+(p[5]>=0xc0);
            } else if (byte==0xc5 && length>=3 && (bits==64 || (p[1]&0xc0)==0xc0)) {
                map=1; op=p[2]; form=length>=4?1+(p[3]>=0xc0):0;
            } else if (byte==0x0f && length>=2) {
                map=1;op=p[1];
            } else if (bits==64 && (byte&0xf0)==0x40 && length>=2) {
                op=p[1];if(op==0x0f && length>=3){map=1;op=p[2];}
            }
            ++counts[{word?2:result.count?1:0,byte,map,op,form,reference>>8}];
            pos+=length; size-=length; ip+=length;
        }
    }
    for (const auto &[key,n]:counts) {
        const auto [stage,byte,map,op,form,id]=key;
        std::printf("%u %u %u %u %u %u %u\n",stage,byte,map,op,form,id,n);
    }
    return cs_close(&h)!=CS_ERR_OK;
}
