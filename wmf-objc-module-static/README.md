# Selected ObjC complete new module remainder

This single-job collector reads the remaining 826 complete `__text` functions
(43,558 instruction words) from the already selected iOS 26.5 / 23F77 arm64
`libobjc.A.dylib`. It reuses the prior 18 closed function intervals and hashes;
those bodies, prior metadata, raw contexts and disassemblies are not recollected.

The whole-file hash, selected-slice hash, UUID, complete text section and every
function boundary are pinned. The new frontier explicitly includes
`objc_retain`, `objc_retain_x8` and `objc_release_x23`. Nine new profile/frontier
boundary tests run. The completed Core module's interval and section helpers
are reused byte-for-byte; no earlier Core, malloc or ObjC test suite reruns.

Only new code intervals and missing noncode section bytes are exported. The
collector lists installed runtimes and reads files; it never boots a Simulator,
loads or executes WMF, executes any provider function, uploads a complete Apple
provider file, or changes production source. Mutable callback values, valid
objects and memory, aliasing, ownership, lifetime, effects and formal source
qualification are separate obligations. Static code coverage proves none of
those properties by itself.

The branch is independent. Automatic continuation remains paused. Publication
and this new job require their own single-job human approval.
