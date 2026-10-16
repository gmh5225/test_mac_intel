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

These checks do not prove equivalence to the original client's full helper
implementation, supervisor, optional observer, or native dispatcher.

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

This additional artifact contains diagnostics and authored recipes only. It
uploads neither the captured client nor recovered client source. The public
helper's optional observer, external signal forwarding and rebuilt client
integration remain separate work.
