# Prepared new allocator backend and failure-tail domain

This follow-up requires a separate approval. The previously approved single job
41283555311 has completed; no second job has been started. Recurring WMF work
remains paused. Proposed destination: `gmh5225/test_mac_intel`, new branch
`codex/wmf-allocator-backend-static`, based on the exact approved parent
`9bb919955385ea193e1a92c46a5bba90d8bf7212`.

Collect the actual LibSystem re-export load commands and raw export payloads,
the two libsystem_malloc typed allocator definitions, two previously uncollected
SwiftCore failure-tail functions, and the Objective-C allocation/release targets.
Follow two direct callee layers, capped at 128 new functions per provider.
Retain every indirect and deferred edge; no complete call closure is assumed.

Core must retain the exact prior whole-file and ARM64 slice hashes. The eight
closed Core functions are referenced by their complete hashes and never
redisassembled. No old inventory or original NeverD Pipeline is rerun. The
existing pinned parser and command recorder are reused without source changes.

Only a read-only runtime-path query and LLVM static disassembly run. No Simulator
device is created or booted; no original app, generated C, or provider function
executes. Full provider binaries stay in temporary runner files and are removed.
The artifact contains selected new function bytes and raw metadata.

New malloc file identities are observations, not guesses from their path or
symbol names. LibSystem re-export resolution, actual symbol interposition,
allocation region/freshness/validity, original provider binding, object values,
callback effects and lifetime remain independent obligations.
