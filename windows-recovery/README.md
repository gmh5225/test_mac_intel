# Native Windows recovery environment

The workflow qualifies Windows x64 and ARM64 hosts for the Claude Code 2.1.296
reconstruction effort. Its first stage runs authored fixtures and an official
Bun 1.4.3 runtime pinned by archive and executable SHA-256.

It builds the PE graph adapters with MSVC, independently rebuilds the same
authored graph twice, and checks original virtual paths, text encodings,
module identity, live bindings and worker resource loading. The generated
program is a fixture, not Claude Code. No source samples or executable files
are uploaded; the artifact contains diagnostic output and a JSON receipt.

The next stage qualifies a capability-free AppContainer with a Job Object:
fresh HOME/work/temp writes, denied host-canary reads and binary-directory
writes, denied IPv4/IPv6 loopback, identical source-graph behavior, bounded
execution and descendant collection. A positive control proves the tested
files and network listeners were accessible outside the container.

Only after those controls pass does the runner download the published,
hash-pinned Windows package, extract source and assets with a helper checked
against NeverD's manifests, and rebuild with the independent pinned runtime.
Two native builds must match each other and the local cross-build. All 2,586
module rows are read back before three original/rebuilt smoke cases run in
fresh AppContainers. No original prefix, bytecode, or prelinked cache is reused.

Only diagnostics under `windows-evidence/evidence` are uploaded. Captured
source, original executables and rebuilt executables stay in the disposable
runner workspace. The full offline behavior matrix and retained native-addon
checks remain separate acceptance steps; smoke checks do not close the goal.

The existing Intel HVF workflows are unrelated and retain their current state.
