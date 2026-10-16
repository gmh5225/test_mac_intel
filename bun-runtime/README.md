# Native Bun reconstruction

The pinned public source is Bun
[`c6da4a4d3010e5553438c60f6bd76d981976867c`](https://github.com/oven-sh/bun/commit/c6da4a4d3010e5553438c60f6bd76d981976867c).
The original client reports a different revision, `eecfd55deb`; this project
does not claim to have recovered that unpublished source revision.

`role_contract.rs` reconstructs the observed Linux selector: exact raw ARGV0
spelling, unconditional consumption of that variable when present, and
recognized actual argv[0] basename precedence. The four role values are rg,
ug/ugrep, bfs and apply-seccomp. Its Rust type names are authored.

`patch_bun.py` requires the exact public process-entry hash before changing
one boundary. `recovered_multicall.rs` runs there before VM/thread setup and
embeds pinned, source-built Linux rg and apply-seccomp ELF payloads. It seals
an anonymous descriptor and replaces its own process image without a host
temporary pathname. This differs from the original static-library linkage.
Ugrep and bfs currently fail explicitly as unintegrated implementations.

The source workflow uses fresh Bun source/build/cache directories in pinned
native compiler containers. The containers supply toolchains; the engine's
core object files are rebuilt. JavaScriptCore may still be a pinned public
prebuilt dependency, as permitted by Bun's upstream build. Public binaries and
diagnostics are the only workflow artifacts. Captured clients and source are
never committed or uploaded.

A passing build and the eight public controls are prerequisites for later
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
reconstruction. The embedded search payload uses the independently rebuilt
static GNU profile, with PCRE2 10.45 JIT on both architectures. Both embedded
payloads must have neither an ELF interpreter nor DT_NEEDED entries. This keeps
a dependency's loader requirement from defeating the core's portability check.
The exact public payload hashes are pinned per architecture; their native
producer is run 38955193889 at 4a39b2d7773ba6b43b36ed04863385d9779bb5e5.
The first focal-sysroot core builds pass the GLIBC_2.17 check on both native
runners (run 38952068043); their earlier dynamic search payload does not inherit
that portability claim. Each new embedded-payload combination still requires
a fresh engine build and the complete captured-client acceptance suite.
