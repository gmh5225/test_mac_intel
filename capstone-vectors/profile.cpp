#include <capstone/capstone.h>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <map>
#include <string>
#include <vector>

int main(int argc, char **argv) {
    if (argc != 4) return 1;
    const int bits = std::stoi(argv[1]);
    std::ifstream input(argv[2], std::ios::binary), ranges(argv[3]);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(input), {}};
    csh handle;
    if (cs_open(CS_ARCH_X86, bits == 16 ? CS_MODE_16 : bits == 32 ? CS_MODE_32 : CS_MODE_64, &handle) != CS_ERR_OK ||
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK) return 2;
    cs_insn *record = cs_malloc(handle);
    if (!record) return 3;
    std::map<std::string,uint64_t> counts;
    size_t start, length;
    uint64_t ip;
    while (ranges >> start >> length >> ip) {
        if (start > bytes.size() || length > bytes.size()-start) return 4;
        const uint8_t *p = bytes.data()+start;
        while (length) {
            const auto *before=p;
            const auto before_size=length;
            const auto before_ip=ip;
            if (!cs_disasm_iter(handle,&p,&length,&ip,record)) {
                if (p!=before || length!=before_size || ip!=before_ip) return 5;
                ++counts["invalid|||"]; ++p; --length; ++ip; continue;
            }
            const auto &x = record->detail->x86;
            std::string key(record->mnemonic);
            key += '|';
            for(unsigned i=0;i<x.op_count;i++) {
                const auto &op=x.operands[i];
                key += op.type==X86_OP_REG?'r':op.type==X86_OP_MEM?'m':op.type==X86_OP_IMM?'i':'?';
                key+=std::to_string(op.size);
            }
            key += '|';
            unsigned lead=0;
            while(lead < record->size) {
                uint8_t ch=record->bytes[lead];
                if (ch==0x66||ch==0x67||ch==0xf0||ch==0xf2||ch==0xf3||ch==0x2e||ch==0x36||ch==0x3e||ch==0x26||ch==0x64||ch==0x65||(bits==64&&(ch&0xf0)==0x40)) {
                    char prefix[3];std::snprintf(prefix,sizeof(prefix),"%02x",ch);key+=prefix;++lead;
                } else break;
            }
            key += '|';
            if (lead < record->size) {
                char op[3];std::snprintf(op,sizeof(op),"%02x",record->bytes[lead]);key+=op;
            }
            ++counts[key];
        }
    }
    if (!ranges.eof() || counts.empty()) return 6;
    for(const auto &v:counts) std::printf("%llu\t%s\n",(unsigned long long)v.second,v.first.c_str());
    cs_free(record,1);
    cs_close(&handle);
}
