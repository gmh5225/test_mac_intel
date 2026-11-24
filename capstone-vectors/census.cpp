#include <capstone/capstone.h>
#include "arch/X86/X86ScanAdapter.h"
#include <array>
#include <cinttypes>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#include <cstring>
extern "C" uint64_t probe_miss[4096], probe_hit[4096], primary_hit[4096];

int main(int argc,char **argv){
    if(argc!=3)return 1;
    std::ifstream text(argv[1],std::ios::binary);
    std::vector<uint8_t> bytes{std::istreambuf_iterator<char>(text),{}};
    if(bytes.empty())return 2;
    for(unsigned path=0;path<2;++path){
        csh handle; if(cs_open(CS_ARCH_X86,CS_MODE_64,&handle)||cs_option(handle,CS_OPT_TEXT,CS_OPT_OFF))return 3;
        cs_insn *record=cs_malloc(handle);if(!record)return 3;
        memset(probe_miss,0,sizeof(probe_miss));memset(probe_hit,0,sizeof(probe_hit));memset(primary_hit,0,sizeof(primary_hit));
        uint64_t hash=14695981039346656037ULL, count=0, size=0;
        std::ifstream ranges(argv[2]);size_t start,length;uint64_t address;
        while(ranges>>start>>length>>address){
            if(!length || start>bytes.size()||length>bytes.size()-start)return 4;
            const uint8_t *p=bytes.data()+start;size_t left=length;
            while(left){
                if(!path){
                    if(!cs_disasm_iter(handle,&p,&left,&address,record))return 5;
                    hash=(hash^((record->id<<8)|record->size))*1099511628211ULL;
                    size+=record->size;++count;
                }else{
                    std::array<uint32_t,256> out;
                    auto n=X86_scanNativeBatch(handle,p,left,address,out.data(),out.size());
                    if(!n.count||n.count>out.size()||n.bytes>left||!n.bytes)return 6;
                    size_t consumed=0;
                    for(size_t i=0;i<n.count;i++){hash=(hash^out[i])*1099511628211ULL;consumed+=out[i]&255;}
                    if(consumed!=n.bytes)return 7;
                    size+=n.bytes;count+=n.count;p+=n.bytes;left-=n.bytes;address+=n.bytes;
                }
            }
        }
        std::cout<<"path "<<path<<" "<<count<<" "<<size<<" "<<hash<<"\n";
        for(unsigned i=0;i<4096;i++)if(probe_miss[i]||primary_hit[i])
            std::cout<<i<<" "<<probe_miss[i]<<" "<<probe_hit[i]<<" "<<primary_hit[i]<<"\n";
        cs_free(record,1);cs_close(&handle);
    }
}
