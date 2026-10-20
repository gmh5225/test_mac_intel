# Native x64 clipboard module comparison

The owned workflow compares two privately reconstructed clipboard modules
with the exact originals from the pinned public Linux GNU and musl packages.
The original module is extracted as data; the captured client is never run.
Private frontend source and complete clients are never workflow inputs or
public artifacts. The small module/fixture bundle arrives through temporary
repository secrets and is checked before use.

The same retained comparison programs exercise fifteen cohorts for each libc:
argument conversion, module cache/exports, missing displays, owned X11 and
Wayland selections, writer replacement, four stranded readers, timeout and
exit lifetime, controlled thread-creation failure, one-chunk INCR, and the
inclusive 100,000,000-byte text limit. The size boundary uses a complete X11
property. Long INCR stress is retained as a separate upstream-backend timing
limitation, not silently retried or treated as successful coverage. Each libc
has 91 function-observation pairs; both profiles total 182.

Before any original call, owned probes require three real pthread callbacks
and one finalizer, including the inactive fault-preload path. All displays and
Wayland servers belong to the disposable offline container. The process is
non-root, with no capabilities, no new privileges, a read-only root, no network,
128 PIDs, 3 GiB memory, two CPUs and bounded child streams/time. No host display,
physical clipboard, audio device or real service is connected.

The owned N-API, fault and Wayland fixtures are prebuilt with the recorded
public sources and pinned toolchain, transferred by hash, and requalified on
the native runner. Their sources and licenses are retained here for review.
Wayland Cargo files are named `wayland-Cargo.toml` and `wayland-Cargo.lock`;
`wayland-source/` is the corresponding `src/` tree. The attributed test state
comes from wl-clipboard-rs 0.9.4; the independent caller uses 0.9.3.

Raw records are indexed and encrypted with the owner's existing CMS
AES-256-GCM / RSA-4096 OAEP recipient. Only the opaque envelope and aggregate
status are uploaded. The decryption key stays local. Successful retention is
followed by removal of the temporary input secrets; another run requires
reprovisioning them. Exact erased private types and the private Bun producer
revision are not established by this workflow.
