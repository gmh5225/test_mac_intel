# Public UIKit trait metadata transport

This independent branch compiles three authored public `.self` queries to LLVM
IR and SIL for ARM64 iOS, ARM64/x86-64 iOS Simulator targets, and x86-64 Mac
Catalyst. Compilation is serial. It preserves the complete outputs, compiler
identity and exact public SDK UIKit/UIKitCore `.tbd` export declarations.

The job has read-only repository permissions. It never boots a Simulator or
executes an original WMF binary, runtime provider, or generated original C.
Only compiler ABI declarations are checked here. Independent readers must
authenticate exports before any product catalog or recovery claim. Enum/value
layout, frame extent, lifetime, noescape and runtime behavior are not inferred.

The existing scheduled continuation remains paused.
