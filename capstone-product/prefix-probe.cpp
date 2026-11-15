#include "neverd/decode/Decoder.h"

#include <cstdint>
#include <cstdio>
#include <ctime>
#include <stdexcept>
#include <vector>

using namespace neverd;

int main() {
  try {
    for (Arch Target : {Arch::X86, Arch::X64})
      for (unsigned Profile = 0; Profile != 3; ++Profile)
        for (size_t Size : {size_t{4096}, size_t{16384}}) {
          Decoder D;
          if (!D.init(Target))
            throw std::runtime_error("init");
          D.setText(Profile != 0);
          D.setDetail(Profile == 2);
          const std::vector<uint8_t> Bytes(Size, 0x66);
          DecodedInsn Insn{};
          const auto Start = std::clock();
          for (size_t Offset = 0; Offset != Size; ++Offset) {
            const auto *Code = Bytes.data() + Offset;
            const int Result =
                Profile == 0
                    ? D.decodeOneLight(Code, Size - Offset, 0x1000 + Offset, Insn)
                    : D.decodeOne(Code, Size - Offset, 0x1000 + Offset, Insn);
            if (Result)
              throw std::runtime_error("invalid prefix accepted");
          }
          const double Ns = double(std::clock() - Start) * 1e9 / CLOCKS_PER_SEC;
          std::printf("{\"bits\":%u,\"profile\":%u,\"bytes\":%zu,\"cpu_ns\":%.0f}\n",
                      Target == Arch::X64 ? 64 : 32, Profile, Size, Ns);
        }
    return 0;
  } catch (const std::exception &Error) {
    std::fprintf(stderr, "%s\n", Error.what());
    return 1;
  }
}
