// Standalone audit helper for a hash-pinned PE. It never loads input code.
// NeverD remains the authoritative extractor; this helper's rows are compared
// with its previously retained manifests before use in the CI environment.
#define main rawStorageAdapterMain
#include "raw-graph-windows-adapter.cpp"
#undef main

int main(int argc,char **argv) try {
  require(argc==4,"input expected-sha256 fresh-output");
  const auto b=bytes(argv[1]);
  require(hash(b.data(),b.size())==argv[2],"input SHA-256 mismatch");
  const auto g=locateNativeGraph(b);const auto f=g.base+g.size-48;
  require(text(b,f+32,16)=="\n---- Bun! ----\n"&&number(b,f,8)==g.size-48,"graph footer");
  const auto table=number(b,f+8,4),length=number(b,f+12,4),entry=number(b,f+16,4);
  const auto flags=number(b,f+28,4),args=number(b,f+20,4),argLength=number(b,f+24,4);
  require(length&&length%52==0&&table<=g.size-48&&length<=g.size-48-table,"module table");
  require(entry<length/52&&(flags==7167||flags==8191||flags==4479),"qualified graph profile");
  require(argLength==0&&args<g.size-48&&b[g.base+args]==0,"empty compile arguments");
  const fs::path out(argv[3]);require(!fs::exists(out),"fresh output");
  fs::create_directory(out);fs::create_directory(out/"input");
  std::ofstream map(out/"mapping.tsv",std::ios::binary);std::string entryName;
  unsigned javascript=0,assets=0;
  for(uint64_t i=0;i<length/52;i++) {
    const auto at=g.base+table+i*52;
    const auto no=number(b,at,4),nn=number(b,at+4,4),co=number(b,at+8,4),cn=number(b,at+12,4);
    require(no<=table&&nn<table-no&&co<=table&&cn<table-co,"module payload range");
    require(b[g.base+no+nn]==0&&b[g.base+co+cn]==0,"module terminators");
    const auto name=text(b,g.base+no,nn);
    require(name.starts_with("B:/~BUN/root/"),"virtual prefix");portable(name.substr(13));
    if(i==entry)entryName=name;
    const auto encoding=b[at+48],loader=b[at+49],format=b[at+50],side=b[at+51];
    if(loader==1) {
      require(encoding==1&&format==1&&side==0&&
          std::all_of(b.begin()+g.base+co,b.begin()+g.base+co+cn,[](auto c){return c<128;}),
          "ASCII JavaScript source identity");
      ++javascript;
    } else ++assets;
    const auto file="m"+std::to_string(i);
    write(out/"input"/file,Bytes(b.begin()+g.base+co,b.begin()+g.base+co+cn));
    map<<name<<'\t'<<unsigned(loader)<<'\t'<<unsigned(encoding)<<'\t'<<unsigned(format)<<'\t'
       <<unsigned(side)<<'\t'<<file<<'\t'<<cn<<'\t'<<hash(b.data()+g.base+co,cn)<<'\n';
  }
  map.close();require(bool(map),"mapping write");
  require(mapping(out/"mapping.tsv").size()==length/52,"validated extracted map");
  std::cout<<"{\"module_count\":"<<length/52<<",\"source_count\":"<<javascript
           <<",\"asset_count\":"<<assets<<",\"entry_index\":"<<entry
           <<",\"entry\":\""<<entryName<<"\",\"flags\":"<<flags
           <<",\"source_and_assets_only\":true,\"executes_input\":false}\n";
  return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 1;}
