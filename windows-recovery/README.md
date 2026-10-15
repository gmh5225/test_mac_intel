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
module rows are read back before four original/rebuilt smoke cases run in
fresh AppContainers. No original prefix, bytecode, or prelinked cache is reused.

The remaining suite compares seven configuration cases and 22 offline behavior
cases covering tool permissions, hooks, MCP, fragmented protocol messages,
session persistence and interruption. An authored loopback server supplies
fixed responses; every request uses a dummy credential. Its per-profile
loopback exemption is separately qualified against a reachable external TCP
peer, preserves existing exemptions, and is removed after descendant collection.
It allows loopback traffic across ports; it does not grant internet capabilities.
The implementation follows the Windows
[configuration APIs](https://learn.microsoft.com/en-us/windows/win32/api/netfw/nf-netfw-networkisolationsetappcontainerconfig).
Ignored child stdio also needs a per-profile grant on the NUL device, as
identified by [libuv's AppContainer launcher](https://github.com/oven-sh/libuv/blob/8023581113b276e7c1aee3f82da57ca0893faab1/test/appcontainer.c).
The device grant is removed after each run; native Win32 and Bun spawn probes
record the child and pipe boundaries separately.

An authored Node-API module must load before the retained audio addon is
inspected. Retained exports are enumerated but never invoked. Materialized
native bytes must match the pinned input asset.

Only diagnostics under `windows-evidence/evidence` are uploaded. Captured
source, original executables and rebuilt executables stay in the disposable
runner workspace. The full offline behavior matrix and retained native-addon
checks have separate receipts. Only a passing full workflow establishes these
bounded acceptance results; no live model service, recording device or complete
semantic equivalence is claimed.

The existing Intel HVF workflows are unrelated and retain their current state.
