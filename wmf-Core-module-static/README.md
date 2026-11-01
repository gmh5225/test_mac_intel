# Selected SwiftCore: complete new module remainder

This single job statically reads the selected iOS 26.5 / 23F77 arm64 file. Its
UUID and complete file/slice hashes are fixed in `pins.json`. The client SDK
version does not select this profile. A matching loaded-cache UUID does not
assert equality with the collected standalone file header or bytes.

The saved metadata has 21,851 complete `__text` function intervals. Seventeen
functions (341 words) are closed and reused only by hash reference. The job
reads the other 21,834 complete functions (976,352 words), including retain and
release implementations needed by the original storage/error-cell contracts.
It retains every new direct/dynamic branch record. LLVM disassembly is split
at complete function boundaries with a 256 KiB output target. A larger single
function stays whole. No closed body or disassembly is collected again.

Non-code section reads exclude every previously collected byte interval.
Zero-fill declarations remain declarations, not observations of live values.
The existing collector/parser helpers at parent commit
`35ce721a1dcffc05df393c9294a37ba5fe267a16` are reused unchanged. Only the nine
new unit tests run; no old collector tests or successful jobs are restarted.

There is no Simulator boot, provider invocation, original WMF upload/load,
pipeline, or original/generated target-code execution. Collection grants no
valid-region, callback-effect, Error-value, ownership, lifetime or source-call
permission. Complete new functions and actual command failures are preserved
in one artifact, without uploading a complete Apple provider binary.

This new independent job requires its own approval before its branch is pushed.
The recurring automation remains paused.
