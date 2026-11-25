#define main state_driver_main
#include "ppc-states.cpp"
#undef main
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <string>
int main(int argc,char **argv) {
  if(argc!=5)return 1;
  API original(argv[1]), trial(argv[2]);
  std::ifstream in(argv[3],std::ios::binary);
  std::vector<uint8_t> data(std::istreambuf_iterator<char>(in),{});
  if(!in||data.empty())return 2;
  const unsigned policy=std::stoul(argv[4]);bool details=policy>=2;
  Machine a(original,CS_ARCH_PPC,CS_MODE_64,policy!=0,details,false);
  Machine b(trial,CS_ARCH_PPC,CS_MODE_64,policy!=0,details,false);
  if(policy==3){
    if(original.option(a.handle,CS_OPT_DETAIL,CS_OPT_ON|CS_OPT_DETAIL_REAL)||
       trial.option(b.handle,CS_OPT_DETAIL,CS_OPT_ON|CS_OPT_DETAIL_REAL))return 3;
  }
  using Name=decltype(&cs_insn_name);
  auto name_a=(Name)dlsym(original.library,"cs_insn_name");
  auto name_b=(Name)dlsym(trial.library,"cs_insn_name");
  if(!name_a||!name_b)return 4;
  size_t ok=0,bad=0,offset=0,aliases=0,unknown=0;
  std::map<std::string,unsigned> freq;
  uint64_t boundaries=14695981039346656037ull;
  while(offset<data.size()){
    const uint8_t *begin=&data[offset],*p=begin,*q=begin;
    size_t left=data.size()-offset, rest=left;uint64_t pc=0x100000+offset,other_pc=pc;
    cs_insn x,y;cs_detail dx,dy;
    std::memset(&x,0x5a,sizeof(x));x.is_alias=x.usesAliasDetails=x.illegal=false;
    std::memcpy(&y,&x,sizeof(x));std::memset(&dx,0xa5,sizeof(dx));std::memcpy(&dy,&dx,sizeof(dx));
    x.detail=details?&dx:nullptr;y.detail=details?&dy:nullptr;
    bool u=original.iter(a.handle,&p,&left,&pc,&x),v=trial.iter(b.handle,&q,&rest,&other_pc,&y);
    if(x.detail!=(details?&dx:nullptr)||y.detail!=(details?&dy:nullptr))return 5;
    x.detail=y.detail=nullptr;
    if(u!=v||pc!=other_pc||left!=rest||p!=q||original.error(a.handle)!=trial.error(b.handle)||
       std::memcmp(&x,&y,sizeof(x))||std::memcmp(&dx,&dy,sizeof(dx))) {
      std::fprintf(stderr,"PPC record differs at offset %zu policy %u\n",offset,policy);return 6;
    }
    if(u){
      ++ok;if(!x.size||p!=begin+x.size||left+x.size!=data.size()-offset)return 7;
      if(policy&&x.is_alias) {
        ++aliases;
        if(!x.alias_id)++unknown;
        else{
          if(x.alias_id>=PPC_INS_ALIAS_END)return 8;
          const char *first=name_a(a.handle,(unsigned)x.alias_id),*second=name_b(b.handle,(unsigned)y.alias_id);
          if(!first||!second||std::strcmp(first,second))return 9;
          ++freq[first];
        }
      }
      offset+=x.size;
    }else{++bad;offset+=std::min(data.size()-offset,size_t(4));}
    boundaries=(boundaries ^ offset)*1099511628211ull;
  }
  std::cout<<ok<<" "<<bad<<" "<<aliases<<" "<<unknown<<" "<<boundaries<<"\n";
  for(const auto &item:freq)std::cout<<item.first<<" "<<item.second<<"\n";
}
