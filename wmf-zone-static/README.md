# New allocator module remainder and NSError class owner

Prepared for one separately approved read-only job in
`gmh5225/test_mac_intel`, branch `codex/wmf-zone-static-closure`, based on
`62a51a0ae623a4859e4554b42d7e5f08f885ffad`. Automatic continuation stays paused.

Collect every remaining complete `__text` function in the exact previously
observed libsystem_malloc image. Reuse the six closed functions and the complete
metadata/fixup context by exact hash. Group adjacent new functions for LLVM
disassembly without crossing any closed interval. Capture missing noncode
section bytes only; preserve zero-fill declarations separately from file bytes.
This gives local analysis the complete allocator code and initial data without
successive depth-limited collections.

Also collect the five previously uncollected complete SwiftCore class-owner
functions in `[0x6aa0c,0x6ab4c)`, including the actual once callback at `0x6aa7c`.
Its source is the saved complete outline's ADRP/ADD argument computation, not a
guessed function name. Both whole-file/slice identities remain fixed. Existing
function and context disassemblies are not repeated. No Objective-C functions,
LibSystem raw re-export context, or passed prior test suites are recollected.

Only runtime inventory and static LLVM disassembly run. No Simulator is created
or booted and no original WMF, generated C, or target provider function executes.
Temporary provider images are removed; selected static bytes are artifacts.
All commands preserve actual stdout, stderr and status, including real failures.

Initial encoded pointers and complete code do not establish the current zone,
TLS/debug state, dynamic hooks, actual original provider binding, valid memory,
freshness, ownership/lifetime, callback effects or original cell stability. Those
remain separate owning contracts and no production gate is changed here.
