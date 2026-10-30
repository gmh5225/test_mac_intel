# Authored merged Set entry compiler transport

This fixture uses two independently authored NSObject subclasses and four
public insert functions. It compiles the same source bytes as the saved
Swift 6.1.2 component with the distinct Xcode 26.5 toolchain. Five Darwin
targets include ARM64 iOS 17.6 Simulator, macOS ARM64/x64, and Catalyst ARM64/x64.

The job saves complete LLVM IR, SIL, assembly, compiler arguments and exits,
SDK/compiler identities, and hashes of actual Make dependency inputs.
It does not link or execute this source, upload/load the original WMF image,
or export Apple SDK/runtime binary files. Compiler transport observations do
not qualify an original entry ABI, Set value/layout, frame, borrow, lifetime,
provider implementation, effects, or source unit.
