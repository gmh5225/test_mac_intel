# Public seccomp helper reconstruction

Build the unmodified public `apply-seccomp.c` and BPF generator from
[sandbox-runtime at 9520430](https://github.com/anthropics/sandbox-runtime/tree/9520430507ce3c354a71b1518e29e76121407ed1).
The source and Apache license are SHA-256 pinned. libseccomp 2.5.4 headers and
their LGPL license are retained separately; its shared library is used only
by the generator inside the fixed compiler image. The shipped helper is static.

Run on an unprivileged native Linux x64 or ARM64 host with Docker:

```sh
python3 seccomp-helper/build.py --arch x64 --output seccomp-helper-build
```

Both filter architectures must reproduce their pinned bytes. Two independent
compilations of each static executable must match. Compilation runs offline
in a read-only container with capabilities removed. Native controls then
install the filter in their own processes and check socket creation, invalid
io_uring requests, rejection of malformed filters, and inheritance through
exec. They do not connect sockets, create io_uring rings, or alter host policy.
The baseline records pre-existing io_uring denial separately.

The public helper also attempts to run an authored exit-status control using
its own namespace setup. If the runner prevents namespace creation, the
receipt records that limitation. A successful command gets an additional
policy check, PID/user/mount namespace checks, capability checks, child signal
exit relay and missing-executable rejection. `--require-helper-command` makes
an unavailable command path fail the build. The Ubuntu 22.04 jobs require
this path; Ubuntu 24.04 retains its measured namespace restriction. Host
policy is recorded, and the workflow does not change it.

These component controls do not prove whole-function equivalence to the
original helper or restore the original engine's built-in dispatcher.

Public build artifacts contain public sources, licenses, exact inputs, static
executables, receipts and diagnostics.

The separate Ubuntu 22.04 original-role acceptance downloads the SHA-512-pinned
published client only after authored controls qualify an empty-root bubblewrap
boundary. It exposes fixed public runtime libraries, the test executable and
owned fixture directories, with separate network/process/user/mount namespaces.
Seven direct native-role cases and four descriptor-3 cases compare the original
against the public helper. The descriptor route opens the selected executable
with O_PATH and execs `/proc/self/fd/3` under `ARGV0=apply-seccomp`; its payload
control confirms the descriptor is inherited and can be closed before work.
A small
authored exec driver records the outer namespace identities for each invocation,
so the nested namespace check cannot pass merely because two separate tests
have different namespace IDs. Only three kernel-assigned namespace identities
are normalized; PID relationships, capabilities, policy results, exit codes and
all other output remain exact.

Twelve additional cases send TERM, INT, HUP, QUIT, USR1 and USR2 to the
driver's own helper child, checking both default termination and a caught
signal returning 37. Workload readiness and both supervisor signal masks are
confirmed before delivery. Five observer cases cover encoded/no-encoded
commands, missing and disconnected consumers, and real queue backpressure.
Normal events must have exact syscall/path order, including escaped paths,
relative paths and dirfds. Event PIDs must identify the same invocation's
proven owned worker. Telemetry remains best effort; enforcement is checked
separately. There are 28 role/descriptor/supervision cases per architecture.

This artifact contains diagnostics and authored recipes only. It uploads
neither the captured client nor recovered client source.

`patch_descriptor.py` applies the recorded one-function provider change to an
exact hash-pinned recovered readable module. It refuses every other revision.
The edited provider requires an absolute helper path; it retains O_PATH,
descriptor 3, ARGV0 and the existing close-before-payload wrapper. The authored
managed launcher sets that path relative to its own location and checks the
client, search helper and seccomp helper before normal startup. It also handles
the explicit `ARGV0=apply-seccomp` role. Missing, non-executable and symlink
helpers fail with exit 126. CI builds both static launcher variants twice;
the public component build does not execute a reconstructed client.

The separate `claude-bash-sandbox.yml` workflow reconstructs preserved and
all-readable clients privately from the pinned published sample and Bun.
The public formatting recipe contains hashes and whitespace insertions only;
it reproduces previously verified NeverD output without embedding captured
source. All 2,589 selected module/asset records must match on readback, and
the four resulting binary hashes must match the sealed local candidates.

Before client entry, authored controls qualify the empty root, isolated
loopback fixture, writable outer test directories and the complete loader
dependency set. Public executables and their libraries are copied explicitly;
host directories and credentials are not exposed. The actual Bash tool then
runs seven cases against the original and both layouts: enforced policy,
output/error streams with Unicode, exit 37, a pipeline with file I/O, denied
write, denied read and fd 3 closure. Ordered protocol frames, all API request
bodies and exact workspace bytes are compared (28 differential pairs across
both architectures). Only the previously qualified identity/time fields are
normalized. Full Bash call chains pass these declared offline cases; wider
semantics and the overall reconstruction remain open.

`--bash-rg /path/to/pinned/rg` enables that suite in `original_acceptance.py`.
The workflow can rebuild the search dependency from source using the
`rebuild_search` dispatch input, and does so automatically if the retained
public artifact is unavailable. Both paths still require the same binary hash.
