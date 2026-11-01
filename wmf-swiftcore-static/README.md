# SwiftCore static implementation evidence

Prepared for one manual delivery to `gmh5225/test_mac_intel`, on the separate
`codex/wmf-swiftcore-static-contract` branch. This source has not been pushed and
the workflow has not run. The user's foreground work request paused the recurring
`wmf-full` automation; this collection does not resume it.

The current checkpoint forbids new GitHub Actions execution. Delivery and the
single workflow run require the user's approval after reviewing these files.
Nothing here modifies NeverD, its SDKs, original WMF, or the product worktree.

The collector reads the installed iOS Simulator 26.5 / 23F77 SwiftCore file. It
requires ARM64, platform 7, and the exact previously observed candidate UUID
`278DFF77-40C0-3E59-8FE1-7C91FC72144A`. It records the complete whole-file and ARM64
slice hashes, complete load commands, symbol table, function starts, imports,
selected fixup pages, and unwind bytes. A mismatch fails and preserves the actual
diagnostic instead of accepting another runtime image.

The exact seed definitions are `_swift_slowAlloc`,
`_swift_stdlib_isStackAllocationSafe`, and `_swift_willThrowTypedImpl`. Every selected
function uses its complete `LC_FUNCTION_STARTS` interval and all instruction
bytes. The collection follows two layers of direct local callees, retains every
deferred edge and indirect branch, and caps the collection at 128 functions.
An interior entry or missing definition fails. A branch into the middle of a
callee retains that fact while collecting the complete owning interval.

Only `xcodebuild -version`, the read-only `simctl list runtimes`, and
`llvm-objdump` run. No Simulator device is created or booted. No application,
provider function, original WMF, or generated C runs. Thin provider binaries
exist only in the runner's temporary directory and are removed after reading.
The uploaded artifact contains selected function records and metadata, not a
complete Apple provider binary.

This is a candidate implementation artifact. A matching UUID and platform do
not establish that the original WMF ran against it. The collector does not
infer source commit, build macros, allocation regions, freshness, callback
effects, availability, initialized values, ownership, or lifetime. Complete
call closure and the owning consumers remain separate obligations.

Local verification runs only new synthetic MachO inputs; no existing closed
provider inventory, compiler probe, original Pipeline, or old proof is rerun.
