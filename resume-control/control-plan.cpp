#include "neverd/runtime/DarwinArm64eUnwindRow.h"
#include <cstdio>
#include <cstdlib>
int main(int argc,char **argv) {
  if (argc!=3) return 1;
  bool protectedCall=atoi(argv[1]);
  uintptr_t offset=strtoull(argv[2],nullptr,16);
  NDDarwinArm64eExceptionSite site{offset,offset+4,protectedCall};
  NDDarwinArm64eUnwindRow row{};
  row.Signing=protectedCall ? NDArm64eSignedIBWithCFA : NDArm64eUnsigned;
  row.CFAFromFP=row.SavedFP=row.SavedLR=protectedCall;
  row.CFAOffset=protectedCall?16:0;
  row.FPOffset=-16;
  row.LROffset=-8;
  NDDarwinArm64eVectorSaves vectors{};
  vectors.Complete=true;
  size_t count=0;
  auto write = [&](const auto &value){return fwrite(&value,sizeof(value),1,stdout)==1;};
  return !(write(site)&&write(row)&&write(vectors)&&write(count));
}
