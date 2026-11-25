#include "arch/X86/X86SimpleOutput.h"
#include <cstdio>
int main() { std::printf("%zu %zu %zu %zu %zu %zu\n", sizeof(X86SimpleOutput), alignof(X86SimpleOutput), offsetof(X86SimpleOutput,mnemonic), offsetof(X86SimpleOutput,operands), offsetof(X86SimpleOutput,flags), offsetof(X86SimpleOutput,ops)); }
