#include <llvm-c/Analysis.h>
#include <llvm-c/Core.h>
#include <llvm-c/IRReader.h>
#include <llvm-c/Target.h>
#include <llvm-c/TargetMachine.h>

#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  if (argc != 4 || (strcmp(argv[3], "O0") && strcmp(argv[3], "O2")))
    return 2;
  LLVMInitializeX86TargetInfo();
  LLVMInitializeX86Target();
  LLVMInitializeX86TargetMC();
  LLVMInitializeX86AsmParser();
  LLVMInitializeX86AsmPrinter();
  LLVMContextRef Context = LLVMContextCreate();
  char *Error = NULL;
  LLVMTargetRef Target;
  LLVMModuleRef Module;
  LLVMMemoryBufferRef Buffer;
  const char *Triple = "x86_64-unknown-linux-gnu";
  if (LLVMGetTargetFromTriple(Triple, &Target, &Error) ||
      LLVMCreateMemoryBufferWithContentsOfFile(argv[1], &Buffer, &Error) ||
      LLVMParseIRInContext(Context, Buffer, &Module, &Error) ||
      LLVMVerifyModule(Module, LLVMReturnStatusAction, &Error)) {
    fprintf(stderr, "%s\n", Error ? Error : "LLVM input error");
    return 1;
  }
  LLVMCodeGenOptLevel Level = strcmp(argv[3], "O0") == 0
                                  ? LLVMCodeGenLevelNone
                                  : LLVMCodeGenLevelDefault;
  LLVMTargetMachineRef Machine = LLVMCreateTargetMachine(
      Target, Triple, "generic", "+svm,+xsave,+avx", Level,
      LLVMRelocDefault, LLVMCodeModelDefault);
  LLVMSetTarget(Module, Triple);
  if (LLVMTargetMachineEmitToFile(Machine, Module, argv[2], LLVMObjectFile,
                                  &Error)) {
    fprintf(stderr, "%s\n", Error ? Error : "LLVM object error");
    return 1;
  }
  LLVMDisposeTargetMachine(Machine);
  LLVMDisposeModule(Module);
  LLVMContextDispose(Context);
  return 0;
}
