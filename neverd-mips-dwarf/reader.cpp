#include "neverd/types/DWARFTypeImport.h"
#include "llvm/DebugInfo/DWARF/DWARFContext.h"
#include "llvm/Object/ObjectFile.h"

#include <cstdio>

int main(int argc, char **argv) {
  if (argc != 2)
    return 2;
  auto file = llvm::object::ObjectFile::createObjectFile(argv[1]);
  if (!file)
    return 3;
  const auto &object = *file->getBinary();
  auto dwarf = llvm::DWARFContext::create(object);
  auto model = object.getBytesInAddress() == 8 ? neverd::types::DataModel::LP64
                                               : neverd::types::DataModel::ILP32;
  auto library = neverd::types::importDWARFTypes(*dwarf, model);
  if (!library)
    return 4;
  for (const auto name : {"Packet", "Header", "HeaderBits"}) {
    const auto *type = (*library)->find(name);
    if (!type || !type->Record)
      return 5;
    std::printf("%s %s %llu\n", type->Record->Union ? "union" : "struct",
                name, static_cast<unsigned long long>(type->Record->Size));
    for (const auto &member : type->Record->Members)
      std::printf("%s.%s %llu %u\n", name, member.Name.c_str(),
                  static_cast<unsigned long long>(member.BitOffset), member.BitWidth);
  }
  return 0;
}
