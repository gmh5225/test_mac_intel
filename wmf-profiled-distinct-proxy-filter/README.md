# New profiling mode for the same distinct predicate source

The Swift client bytes intentionally remain identical to the completed 6479
unprofiled domain. This is a new compiler instrumentation domain: every new
IR/SIL/assembly invocation adds -profile-generate. The module name and artifact
directory distinguish the new outputs. The same source is compiled again in
the new mode; no claim of zero source recompilation is made. The completed
unprofiled job and outputs are not rerun or replaced.

All five prior authored module binaries and elements source stay byte/hash
identical and are not recompiled. Fifteen serial client commands use the same
compiler and two SDK settings hashes. Version text is reused. The actual
instrumented output, failure boundaries, declarations, counter data and all
instructions must be independently read before any correspondence assertion.

The original image contains a named __llvm_prf_cnts cell at c7fa48, but this
does not prove its exact original compiler version or flags. Original profile
writes, unknown runtime values, ABIs, weak linkage, ownership, frame, provider,
effects and source publication gates remain unchanged. No original or authored
generated machine code, profiler runtime or simulator is executed or linked.
