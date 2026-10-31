# Resilient Set filter client compiler evidence

This isolated compiler fixture compiles the same new public filter client source used in local Swift 6.1.2 evidence, with the previously recorded Xcode 26.5 / Swift 6.3.2 compiler. It imports five immutable, previously successful NDSetExternalElements modules from run 41100731051. Their exact bytes are inputs; modules are not compiled again.

The single serial job plans 15 compiler commands: IR, SIL and assembly for arm64 iOS 17.6 Simulator and arm64/x86_64 macOS 14 and Catalyst 18. It hashes the compiler and both SDK settings before compilation and reuses existing version text. Each actual command, output, exit, complete Make rule and dependency hash is retained. The output artifact is wmf-resilient-set-filter-xcode265-1 for the first attempt.

The payload contains independently authored source, scripts, records and previously compiled authored Swift modules. No original application, original recovered IR or generated C is uploaded. Nothing is linked or executed, and no Simulator is launched. A compiler result alone grants no original ABI, callback, availability, value, layout, borrow, lifetime, effects or source-publication permission.
