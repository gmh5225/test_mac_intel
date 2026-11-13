#include <capstone/capstone.h>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>

extern "C" bool census_output(csh, const uint8_t *, size_t, cs_insn *);

int main(int argc,char **argv) {
    if (argc!=4) return 1;
    csh handle;
    if (cs_open(CS_ARCH_X86,std::stoul(argv[3])==64 ? CS_MODE_64 : CS_MODE_32,&handle) ||
        cs_option(handle,CS_OPT_DETAIL,CS_OPT_ON)) return 2;
    cs_insn *record=cs_malloc(handle);
    std::ifstream file(argv[1],std::ios::binary),ranges(argv[2]);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(file),{}};
    size_t offset, length;
    uint64_t address;
    while (ranges>>offset>>length>>address) {
        if (offset>bytes.size()||length>bytes.size()-offset) return 3;
        const uint8_t *cursor=bytes.data()+offset;
        size_t left=length, records=0, hits=0, invalid=0;
        while (left) {
            const uint8_t *start=cursor;
            size_t available=left;
            if (cs_disasm_iter(handle,&cursor,&left,&address,record)) {
                ++records;
                hits+=census_output(handle,start,available,record);
            } else {
                ++cursor;--left;++address;++invalid;
            }
        }
        std::cout<<records<<' '<<hits<<' '<<invalid<<'\n';
    }
    cs_free(record,1);cs_close(&handle);
}
