// Private PE locator for independent official Bun templates; never loads code.
struct NativeGraph { uint64_t base, size, sectionSizeField; };
NativeGraph locateNativeGraph(const Bytes &b) {
  require(text(b,0,2)=="MZ", "PE DOS header");
  const auto pe=number(b,60,4);
  require(pe>=64 && number(b,pe,4)==0x4550, "PE signature");
  const auto cpu=number(b,pe+4,2), count=number(b,pe+6,2);
  const auto optSize=number(b,pe+20,2), flags=number(b,pe+22,2), opt=pe+24;
  require((cpu==0x8664 || cpu==0xaa64) && count && count<=96 &&
          optSize>=240 && optSize<=4096 && (flags&2) && !(flags&0x2000), "PE executable profile");
  require(number(b,opt,2)==0x20b, "PE64 optional header");
  const auto sa=number(b,opt+32,4), fa=number(b,opt+36,4);
  const auto imageSize=number(b,opt+56,4), headers=number(b,opt+60,4);
  require(fa>=512 && fa<=65536 && !(fa&(fa-1)) && sa>=4096 && sa>=fa &&
          !(sa&(sa-1)) && imageSize && imageSize%sa==0 && headers%fa==0 &&
          headers>=opt+optSize+count*40 && headers<=b.size(), "PE alignment");
  NativeGraph g{}; unsigned found=0;
  for(uint64_t i=0;i<count;++i) {
    const auto at=opt+optSize+i*40, vs=number(b,at+8,4), va=number(b,at+12,4);
    const auto raw=number(b,at+16,4), start=number(b,at+20,4);
    require(start<=b.size() && raw<=b.size()-start && va%sa==0 && va<imageSize &&
            std::max(vs,raw)<=imageSize-va, "PE section bounds");
    if(text(b,at,8)!=std::string(".bun\0\0\0\0",8))continue;
    require(++found==1 && number(b,at+36,4)==0x40000040 &&
            number(b,at+24,8)==0 && number(b,at+32,4)==0 && vs>=56 &&
            start>=headers && start%fa==0 && ((vs+fa-1)&~(fa-1))==raw,
            "PE Bun section profile");
    const auto size=number(b,start,8);
    require(size==vs-8, "PE graph size");
    require(std::all_of(b.begin()+start+vs,b.begin()+start+raw,[](auto c){return c==0;}), "PE padding");
    for(uint64_t j=0;j<count;++j) {
      if(i==j)continue;
      const auto p=opt+optSize+j*40, s=number(b,p+20,4), n=number(b,p+16,4);
      require(!n || start+raw<=s || s+n<=start, "PE overlapping graph");
    }
    g={start+8,size,at+8};
  }
  require(found==1,"PE graph missing");return g;
}
void resizeNativeGraph(Bytes &b, const NativeGraph &g, uint64_t size) {
  const auto opt=number(b,60,4)+24, fa=number(b,opt+36,4);
  require(size<=g.size && size+8<=UINT32_MAX, "PE resized graph bounds");
  set(b,g.base-8,size,8);
  set(b,g.sectionSizeField,size+8,4);
  set(b,g.sectionSizeField+8,(size+8+fa-1)&~(fa-1),4);
}
