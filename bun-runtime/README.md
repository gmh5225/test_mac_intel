# Native Bun reconstruction

The pinned public source is Bun
[`c6da4a4d3010e5553438c60f6bd76d981976867c`](https://github.com/oven-sh/bun/commit/c6da4a4d3010e5553438c60f6bd76d981976867c).
The original client reports a different revision, `eecfd55deb`; this project
does not claim to have recovered that unpublished source revision.

`role_contract.rs` reconstructs the observed Linux selector: exact raw ARGV0
spelling, unconditional consumption of that variable when present, and
recognized actual argv[0] basename precedence. The four role values are rg,
ug/ugrep, bfs and apply-seccomp. Its Rust type names are authored.

`patch_bun.py` requires the exact public process-entry and native-build-graph
hashes before changing either boundary. `recovered_multicall.rs` runs there
before VM/thread setup. It directly calls source-built Rust rg and C seccomp
entries linked into the engine. The Rust library uses Bun's exact compiler
channel and the host's existing Rust standard library/global allocator. Cargo's
fresh reported artifacts define the archive inputs. Ugrep and bfs currently
fail explicitly as unintegrated implementations.

The earlier embedded-ELF strategy passed public component controls but failed
actual Bash: materializing the seccomp payload exceeded the inherited 256 KiB
file limit. That strategy is rejected for client admission. The replacement
executes library code without writing a payload file and must pass ten controls
with RLIMIT_FSIZE=0, the glibc gate and actual captured-client acceptance.

The source workflow uses fresh Bun source/build/cache directories in pinned
native compiler containers. The containers supply toolchains; the engine's
core object files are rebuilt. JavaScriptCore may still be a pinned public
prebuilt dependency, as permitted by Bun's upstream build. Public binaries and
diagnostics are the only workflow artifacts. Captured clients and source are
never committed or uploaded.

A passing build and the ten public controls are prerequisites for later
captured-client graph rebuild, complete readback and original comparisons.
Neither a prepared patch nor these controls establish full recovery.

The first successful native source builds required glibc 2.38 because the
development compiler image had no release sysroot. They remain component-only
evidence and are not admitted to the Ubuntu 22.04 client suite. The builder now
follows the pinned public Bun sysroot specification: exact focal libc/header
debs and the upstream GCC-13 archive, projected into a fresh private directory.
It checks the resulting core's version needs against the upstream glibc 2.17
floor before accepting any runtime. Sysroot projection preserves regular bytes,
defers internal links and refuses traversal or conflicting materialization;
it does not change the runner's libraries or namespace policy.

The sysroot includes every runtime/header package in the pinned GCC archive.
Its three unused GCC compiler driver packages are omitted because Bun uses
the pinned Clang toolchain. This avoids projecting unrelated large compiler
executables. Linux's case-distinct headers require a case-sensitive output
filesystem; an APFS bind-mount collision is retained as a refused local
preparation, and the unchanged projection passes on an owned Linux VM volume.

Both original glibc clients require no version newer than GLIBC_2.17. The
previous standalone glibc rg has GLIBC_2.34 requirements. The first static
musl candidate loses PCRE2 JIT on ARM64, so it is not used for the glibc
reconstruction. The direct-link library package retains exact public Rust crates,
PCRE2 10.45/JIT source, upstream locks, the unchanged seccomp C source/filter
header, the authored ABI wrapper and native probe controls. Every package file
is hashed before integration. Libraries are built offline in the exact pinned
Bun compiler image and combined into an archive without a second Rust standard
library. Native standalone controls do not establish the portability of a
complete Bun link; the final engine must independently pass its version-needs
gate and actual execution tests.

`claude-source-native-client.yml` consumes only independently admitted runtime
profiles in `seccomp-helper/source-runtime-pins.json`. Admission binds the exact
producer, complete artifact manifest, binary, glibc floor and direct library
input hashes. Its private client builds preserve the original descriptor provider;
the readable layout applies only the pinned whitespace recipe. Each layout is
built twice and every module row is read back before actual execution.

The acceptance target calls the source-built engine for all 56 bounded helper
comparisons, including observer and external signal cases, followed by
seven complete Bash tool chains and thirteen built-in Grep/Glob cases against
both layouts. The source-native route calls the rebuilt client directly and
has no external rg on PATH. Captured clients and source stay on the runner;
only diagnostics are uploaded. A prepared workflow or admitted public engine
does not establish that this client acceptance has passed.
