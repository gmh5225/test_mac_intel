#include "arch/X86/X86ScanAdapter.h"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <map>
#include <tuple>
#include <vector>
extern "C" bool observedOutput32(csh, const uint8_t*, size_t, cs_insn*, uint16_t*, unsigned*);
extern "C" bool observedOutput64(csh, const uint8_t*, size_t, cs_insn*, uint16_t*, unsigned*);
struct EffectCensus {
    unsigned read_count{},write_count{},candidates{},comparisons{},duplicates{};
    cs_regs read{},written{};
    void append(uint16_t *regs,unsigned &n,unsigned reg,bool unique=true) {
        ++candidates;
        if(unique) for(unsigned i=0;i<n;++i){
            ++comparisons;
            if(regs[i]==reg){++duplicates;return;}
        }
        regs[n++]=reg;
    }
    bool measure(csh h,cs_insn &insn) {
        const auto &detail=*insn.detail;
        read_count=detail.regs_read_count;
        write_count=detail.regs_write_count;
        std::memcpy(read,detail.regs_read,read_count*sizeof(*read));
        std::memcpy(written,detail.regs_write,write_count*sizeof(*written));
        for(unsigned i=0;i<detail.x86.op_count;++i){
            const auto &o=detail.x86.operands[i];
            if(o.type==X86_OP_REG){
                if(o.access&CS_AC_READ)append(read,read_count,o.reg);
                if(o.access&CS_AC_WRITE)append(written,write_count,o.reg);
            }else if(o.type==X86_OP_MEM){
                if(o.mem.segment!=X86_REG_INVALID)append(read,read_count,o.mem.segment,false);
                if(o.mem.base!=X86_REG_INVALID)append(read,read_count,o.mem.base);
                if(o.mem.index!=X86_REG_INVALID)append(read,read_count,o.mem.index);
            }
        }
        uint8_t nr=0,nw=0;cs_regs rr{},ww{};
        return cs_regs_access(h,&insn,rr,&nr,ww,&nw)==CS_ERR_OK && nr==read_count && nw==write_count &&
            std::memcmp(read,rr,nr*sizeof(*rr))==0 && std::memcmp(written,ww,nw*sizeof(*ww))==0;
    }
};

int main(int argc,char **argv) {
    if (argc != 5) return 1;
    const unsigned bits=std::atoi(argv[1]);
    std::ifstream in(argv[2],std::ios::binary), spans(argv[3]);
    if(!in || !spans) return 2;
    const std::vector<uint8_t> data{std::istreambuf_iterator<char>(in), {}};
    const auto writer=bits==64 ? observedOutput64 : observedOutput32;
    const auto mode=bits==64 ? CS_MODE_64 : CS_MODE_32;
    csh normal=0, fast=0;
    if(cs_open(CS_ARCH_X86,mode,&normal)||cs_open(CS_ARCH_X86,mode,&fast)||cs_option(normal,CS_OPT_DETAIL,CS_OPT_ON)||cs_option(fast,CS_OPT_DETAIL,CS_OPT_ON))return 3;
    cs_opt_mnem custom{X86_INS_UD2,"ud2"};
    if(cs_option(normal,CS_OPT_MNEMONIC,reinterpret_cast<size_t>(&custom))) return 3;
    cs_insn *ref=cs_malloc(normal);
    if(!ref)return 3;
    using Key=std::tuple<unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned,unsigned>;
    std::map<Key,uint64_t> counts;
    using Shape=std::array<unsigned,11>;
    struct Record { uint64_t count{},visits{},comparisons{},duplicates{};std::string bytes; };
    std::map<Shape,Record> shapes;
    unsigned mismatches=0;
    size_t start,n;uint64_t ip;
    while(spans>>start>>n>>ip){
        if(start>data.size()||n>data.size()-start)return 4;
        const uint8_t *p=data.data()+start;
        while(n) {
            auto next=p;auto left=n;auto address=ip;
            ref->is_alias=false;ref->usesAliasDetails=false;ref->illegal=false;
            const bool valid=cs_disasm_iter(normal,&next,&left,&address,ref);
            cs_detail detail{};cs_insn text{},built{};
            text.address=built.address=ip;built.detail=&detail;
            uint16_t size_text=0,size_detail=0;
            unsigned text_path=0,detail_path=0;
            const bool text_hit=writer(fast,p,n,&text,&size_text,&text_path);
            const bool detail_hit=writer(fast,p,n,&built,&size_detail,&detail_path);
            auto equal=[&](const cs_insn &out,unsigned size) {
                return valid && size==ref->size && out.id==ref->id && out.size==size && !std::strcmp(out.mnemonic,ref->mnemonic) && !std::strcmp(out.op_str,ref->op_str);
            };
            if((text_hit&&!equal(text,size_text))||(detail_hit&&!equal(built,size_detail))){
                if(++mismatches<=10) {
                    std::fprintf(stderr,"mismatch @%llx ",(unsigned long long)ip);
                    for(size_t i=0;i<(n<15?n:15);++i)std::fprintf(stderr,"%02x",p[i]);
                    std::fprintf(stderr," expected %d %u %s %s found %u %s %s\n",valid,ref->size,ref->mnemonic,ref->op_str,size_text,text.mnemonic,text.op_str);
                }
            }
            const unsigned len=valid ? ref->size : 1;
            if(!len || len>n || (valid&&(next!=p+len||left!=n-len)))return 5;
            const auto &x=ref->detail->x86;
            unsigned operands=0,flags=0;
            if(valid){
                for(unsigned i=0;i<x.op_count;++i)operands=operands*8+unsigned(x.operands[i].type);
                flags=(x.encoding.disp_size!=0) | ((x.encoding.imm_size!=0)<<1);
                if(x.encoding.modrm_offset){
                    const auto mr=p[x.encoding.modrm_offset];
                    flags|=(mr<0xc0 ? ((mr&7)==4?2u:1u) : 3u)<<2;
                }
            }
            const unsigned status=valid?(1+text_hit+2*detail_hit):0;
            unsigned primary=p[0],opcode=primary,map=0;
            unsigned pos=0;
            while(pos+1<len && (p[pos]==0x66||p[pos]==0xf2||p[pos]==0xf3||p[pos]==0x67||(bits==64&&(p[pos]&0xf0)==0x40)))++pos;
            opcode=p[pos];
            if(opcode==0x0f && pos+1<len){map=1;opcode=p[++pos];if((opcode==0x38||opcode==0x3a)&&pos+1<len){map=opcode==0x38?2:3;opcode=p[++pos];}}
            else if(opcode==0x62&&pos+5<len&&(bits==64||(p[pos+1]&0xc0)==0xc0)){map=p[pos+1]&15;opcode=p[pos+4];}
            else if(opcode==0xc4&&pos+3<len&&(bits==64||(p[pos+1]&0xc0)==0xc0)){map=p[pos+1]&31;opcode=p[pos+3];}
            else if(opcode==0xc5&&pos+2<len&&(bits==64||(p[pos+1]&0xc0)==0xc0)){map=1;opcode=p[pos+2];}
            if(text_path!=detail_path)return 8;
            if(valid) {
                if(detail_hit && std::memcmp(&detail,ref->detail,offsetof(cs_detail,x86)+sizeof(cs_x86))!=0)return 9;
                EffectCensus effects;if(!effects.measure(normal,*ref))return 10;
                unsigned vec=0;
                if(primary==0x62 && len>=6)vec=((p[2]&0x83)<<8)|(p[3]&0xf7);
                if(primary==0xc4 && len>=5)vec=p[2]&0x87;
                if(primary==0xc5 && len>=4)vec=p[1]&7;
                const unsigned mem=x.encoding.modrm_offset?p[x.encoding.modrm_offset]>>6:4;
                const unsigned implicit=(ref->detail->regs_read_count<<8)|ref->detail->regs_write_count;
                unsigned access=0;
                for(unsigned i=0;i<x.op_count;++i)access=(access<<2)|(x.operands[i].access&3);
                Shape shape{text_path,primary,map,opcode,ref->id,operands,flags,mem,vec,implicit,access};
                Record &v=shapes[shape];++v.count;v.visits+=effects.candidates;v.comparisons+=effects.comparisons;v.duplicates+=effects.duplicates;
                if(v.bytes.empty()){
                    constexpr char hex[]="0123456789abcdef";
                    for(unsigned j=0;j<len;++j){v.bytes+=hex[p[j]>>4];v.bytes+=hex[p[j]&15];}
                }
            }
            ++counts[{status,primary,map,opcode,valid?ref->id:0,operands,flags,len,valid?x.op_count:0}];
            ip+=len;p+=len;n-=len;
        }
    }
    for(const auto &[k,total]:counts){
        const auto [status,primary,map,op,id,operands,flags,len,nops]=k;
        std::printf("%u %u %u %u %u %u %u %u %u %llu\n",status,primary,map,op,id,operands,flags,len,nops,(unsigned long long)total);
    }
    std::ofstream shape_file(argv[4]);
    for(const auto &[shape,row]:shapes){
        for(auto field:shape)shape_file<<field<<' ';
        shape_file<<row.count<<' '<<row.visits<<' '<<row.comparisons<<' '<<row.duplicates<<' '<<row.bytes<<'\n';
    }
    if(!shape_file)return 11;
    std::fprintf(stderr,"%u writer output mismatches\n",mismatches);
    cs_free(ref,1);cs_close(&normal);cs_close(&fast);return mismatches?7:0;
}
