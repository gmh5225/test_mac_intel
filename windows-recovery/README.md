# Native Windows recovery environment

The workflow qualifies Windows x64 and ARM64 hosts for the Claude Code 2.1.296
reconstruction effort. Its first stage runs authored fixtures and an official
Bun 1.4.3 runtime pinned by archive and executable SHA-256.

It builds the PE graph adapters with MSVC, independently rebuilds the same
authored graph twice, and checks original virtual paths, text encodings,
module identity, live bindings and worker resource loading. The generated
program is a fixture, not Claude Code. Captured source samples and client
executables are never uploaded; client artifacts contain diagnostic output
and JSON receipts.

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

The editable-source probe changes one unique CLI version literal in a separate
copy of the captured source. Both the before/after source hashes and the complete
edited module inventory are pinned. Two independent native rebuilds must match
the local editable cross-build, all 2,586 rows are read back, and the modified
version output must run in the same capability-free AppContainer. This proves
that the edited source is used by the executable; it does not establish
equivalence for arbitrary edits or restore erased source names and types.

The all-readable stage builds the shared NeverD source recovery owner from the
pinned public commit in `formatter_bundle.py`. Five owner tests must pass before
the formatter and matching MSVC runtime libraries are packaged. Both native
hosts verify every file against the manifest hash passed by the producing job,
then run seven authored formatting/refusal controls. Windows ARM64 executes
this x64 analysis tool under Windows emulation; the client runtime and both
client rebuilds still use native ARM64 Bun.

Every one of the 2,343 JavaScript sources is formatted by that owner with a
same-parser-tree check. All source/asset rows must match the locally verified
all-readable selection. Two independent native rebuilds must match the pinned
local build; all 2,586 rows are then extracted and compared again. Four smoke,
seven configuration and 22 offline behavior cases compare the original against
this all-readable executable in fresh disposable state. Baseline observations
and the all-readable observations have separate diagnostic directories.

Fourteen additional Read/Edit cases run against the original and both source
layouts, adding 28 differential pairs per architecture. The exact matrix is
shared with the Linux qualification: ranged UTF-8 reads, missing and directory
errors, one/all replacements, ambiguity, CRLF and Unicode bytes, absent old
strings, and model/Read-permission/read-cache conditions. Every case checks
ordered protocol and API records, tool error states, and complete workspace
file bytes using the existing strict normalizer. The sequential HTTP fixture
must pass authored rendering/refusal controls and a native Bun round trip in
AppContainer before a captured client is executed. `core-tool-acceptance.json`
records these additional results separately.

Seven further cases exercise the actual token-cap marker, multiline and
UTF-16-safe long-line truncation, explicit-range rejection, model-dependent
Edit guards, and replacement of a partial cache entry by a small ranged Read.
These declare `CLAUDE_CODE_FILE_READ_MAX_OUTPUT_TOKENS=8` while the authored
count-tokens endpoint reports ten tokens. Each verifies that counting was
exercised, the true truncation flag and a strict content prefix are present,
Unicode pairs stay complete, and exact file bytes and ordered wire records
match both layouts. `read-truncation-acceptance.json` records the seven-case
supplement separately. Bash, Grep, Glob, default-limit stress cases and live
services remain outside these matrices.

The suite compares seven configuration cases and 22 offline behavior
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

Only client diagnostics under `windows-evidence/evidence` are uploaded. A
separate artifact holds the publicly built formatter, licenses, owner-test
result and exact runtime libraries. Captured
source, original executables and rebuilt executables stay in the disposable
runner workspace. The full offline behavior matrix and retained native-addon
checks have separate receipts. Only a passing full workflow establishes these
bounded acceptance results; no live model service, recording device or complete
semantic equivalence is claimed.

The existing Intel HVF workflows are unrelated and retain their current state.
