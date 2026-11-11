#include "FuncDetectorDetail.h"
#include "neverd/decode/Decoder.h"
#include "neverd/loader/Loader.h"
#include "llvm/Support/Error.h"
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <set>
#include <vector>
#include <ctime>
using namespace neverd;
int main(int argc,char**argv){
  if(argc!=3)return 2;
  auto loader=Loader::create(argv[1]);if(!loader)return 3;
  auto image=loader->load(argv[1]);if(!image){llvm::consumeError(image.takeError());return 4;}
  const BinaryImage &img=*image;Decoder dec;if(!dec.init(img))return 5;
  dec.setText(false);dec.setDetail(false);
  auto walk=[&](){std::set<va_t> calls;std::vector<std::pair<va_t,va_t>> addresses;
    for(const Segment& seg: img.Segments)if(seg.isExecutable()&&!seg.Data.empty())
      func_detect_detail::scanSegmentCallsX86(img,dec,&seg,seg.VA,seg.VA+std::min<uint64_t>(seg.Size,seg.Data.size()),calls,addresses);
    if(calls.empty()||dec.detailEnabled()||dec.textEnabled())std::abort();uint64_t ch=0,ah=0;
    for(va_t v:calls)ch=(ch^v)*UINT64_C(0x100000001b3);
    for(auto [from,to]:addresses)ah=((ah^from)*UINT64_C(0x100000001b3)^to)*UINT64_C(0x100000001b3);
    return std::array<uint64_t,4>{calls.size(),ch,addresses.size(),ah};};
  auto expected=walk();int repeats=std::atoi(argv[2]);auto start=std::clock();for(int i=0;i<repeats;++i)if(walk()!=expected)std::abort();auto elapsed=std::clock()-start;
  std::cout<<uint64_t(elapsed)<<' '<<repeats;for(auto v:expected)std::cout<<' '<<v;std::cout<<'\n';
}
