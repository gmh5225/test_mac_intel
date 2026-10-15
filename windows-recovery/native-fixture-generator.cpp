// Private self-authored embedded Node-API loader probe. Never calls device APIs.
#define main unusedRawAdapterMain
#include "raw-graph-windows-adapter.cpp"
#undef main
int main(int argc,char**argv)try{
 require(argc>=5&&(argc-3)%2==0,"output proof-or-inspect virtual-name addon-file pairs");
 fs::path out=argv[1];require(!fs::exists(out),"fresh output");fs::create_directories(out/"source");
 bool proof=std::string(argv[2])=="proof";require(proof||std::string(argv[2])=="inspect","mode");
 std::string names="[",rows;unsigned index=1;
 for(int i=3;i<argc;i+=2,++index){
  std::string name=argv[i];require(name.starts_with("B:/~BUN/root/"),"virtual prefix");portable(name.substr(13));
  auto body=bytes(argv[i+1]);auto file="native-"+std::to_string(index)+".bin";write(out/"source"/file,body);
  if(i!=3)names+=",";names+="\""+name+"\"";
  rows+=name+"\t10\t0\t0\t1\t"+file+"\t"+std::to_string(body.size())+"\t"+hash(body.data(),body.size())+"\n";
 }
 names+="]";
 std::string source="const names="+names+";\nconst selfAuthored="+(proof?"true":"false")+R"JS(;
const rows=[];
for(const name of names){
 try{
  const value=import.meta.require(name);
  const descriptors=Object.getOwnPropertyDescriptors(value);
  const properties=Object.getOwnPropertyNames(descriptors).sort().map(name=>{
   const d=descriptors[name];return {name,kind:Object.hasOwn(d,'value')?typeof d.value:'accessor',
     enumerable:d.enumerable,configurable:d.configurable,writable:d.writable??null,
     getter:typeof d.get==='function',setter:typeof d.set==='function'};
  });
  const row={name,loaded:true,properties,sameCachedInstance:value===import.meta.require(name),
    originalExportFunctionsInvoked:false};
  if(selfAuthored)row.proof=value.proof();
  rows.push(row);
 }catch(error){rows.push({name,loaded:false,error:String(error),originalExportFunctionsInvoked:false});}
}
console.log(JSON.stringify({main:Bun.main,embedded:Bun.embeddedFiles.map(f=>f.name).sort(),rows}));
)JS";
 Bytes body(source.begin(),source.end());write(out/"source/entry.js",body);
 std::ofstream mappingFile(out/"mapping.tsv");mappingFile<<"B:/~BUN/root/native-acceptance\t1\t1\t1\t0\tentry.js\t"<<body.size()<<'\t'<<hash(body.data(),body.size())<<'\n'<<rows;
 require(bool(mappingFile),"map write");return 0;
}catch(const std::exception&e){std::cerr<<e.what()<<'\n';return 2;}
