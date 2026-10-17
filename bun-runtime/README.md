# Native Bun reconstruction

The pinned public source is Bun
[`c6da4a4d3010e5553438c60f6bd76d981976867c`](https://github.com/oven-sh/bun/commit/c6da4a4d3010e5553438c60f6bd76d981976867c).
The original client reports a different revision, `eecfd55deb`; this project
does not claim to have recovered that unpublished source revision.

`role_contract.rs` reconstructs the observed Linux selector: exact raw ARGV0
spelling, unconditional consumption of that variable when present, and
recognized actual argv[0] basename precedence. The four role values are rg,
ug/ugrep, bfs and apply-seccomp. Its Rust type names are authored.

`patch_bun.py` checks exact public entry, C build, Cargo, Rust planner and
source-glob hashes. `recovered_multicall.rs` dispatches before VM/thread setup.
The rg source is a dependency of bun_runtime, using Bun's own source-built std
and linker-plugin LTO graph. Seccomp remains the unchanged C implementation.
No prebuilt Rust archive is a link input. The default profile still rejects
Ugrep/bfs explicitly. A separately qualified Bfs C library integration profile
is described below; it has not yet passed full-engine acceptance.

The filename/count crash has been traced on the public ARM64 engine to
`std::fs::canonicalize`: libc `realpath(NULL)` allocated on the libc heap,
while the executable's local `free` was mimalloc. The public linker script
hid the malloc override from libc. A native source model rejects both hidden
symbols and symbols versioned as `BUN_1.2`; the matching GLIBC versions pass
100 realpath/getcwd/getline ownership checks. `allocator_exports.py` now
exports the ten allocator functions with each architecture's libc ABI versions.
Fresh engines must pass a dynamic symbol/version check and 768 actual rg
filename, count, JSON and inherited-file-descriptor comparisons with
RLIMIT_FSIZE=0. This source fix still requires native full-engine and complete
client acceptance; the earlier crashing engines are not repaired artifacts.

Standalone Rust/C hosts passed seven RLIMIT_FSIZE=0 controls. The first full Bun
link rejected those separately compiled archives: Bun rebuilds std with its own
features and flags. The replacement stages the pinned public rg/PCRE2 source
archives and ABI wrapper into the same Rust graph. Two native bootstrap plans
resolved the same effective Cargo.lock, preserving every original package and
checksum while adding 24 packages. That exact lock is now an input, so all
planning and compilation use --locked with the public Rust planner unchanged.
A pre-build graph verifier requires one target std,
the actual rg dependency edge and the pinned PCRE2 overlay source. The effective
Cargo.lock and complete plan are retained for independent readback and repeat
build qualification.

The shared graph compiled rg on both architectures before exposing six Bun
`as _` comparisons whose inference became ambiguous with serde_json's trait
implementations. Exact source hashes and line identities gate explicit i32
address-family and u16 SystemError casts. Separate i32 syscall errors are not
rewritten. Run 38989752164 rebuilt both native engines and passed all ten
zero-file-budget controls with PCRE2 10.45/JIT and GLIBC_2.17. All source,
artifact, lock and graph records were independently rehashed before admission.

The earlier embedded-ELF strategy failed real Bash when materializing a payload
exceeded the inherited 256 KiB hard file limit. That strategy is rejected. The
source graph still has to pass ten zero-file-budget engine controls, the glibc
gate and every actual client case; neither standalone hosts nor a graph patch
establish that acceptance.

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
is hashed before integration. The standalone library proof remains source provenance and
component evidence only. The engine recompiles Rust sources and std together; the final engine must independently pass its version-needs
gate and actual execution tests.

`claude-source-native-client.yml` consumes only independently admitted runtime
profiles in `seccomp-helper/source-runtime-pins.json`. Admission binds the exact
producer, complete artifact manifest, binary, glibc floor, source graph and
input hashes. Rejected engines have no admitted profile. Its private client builds preserve the original descriptor provider;
the readable layout applies only the pinned whitespace recipe. Each layout is
built twice and every module row is read back before actual execution.

The acceptance target calls the source-built engine for all 56 bounded helper
comparisons, including observer and external signal cases, followed by
seven complete Bash tool chains and thirteen built-in Grep/Glob cases against
both layouts. The source-native route calls the rebuilt client directly and
has no external rg on PATH. Captured clients and source stay on the runner;
only diagnostics are uploaded. Run 38991982622 rebuilt both layouts twice on
both architectures and passed all 28 real Bash comparisons and the helper
controls. It failed built-in search: G03-count returned no matches for one x64
layout and one ARM64 layout while the originals returned two. Those exact raw
records remain failed evidence. The current diagnostic run retains client
debug logs and independently probes count output through synchronous and
asynchronous children, both with ordinary paths and inherited FD3.

The optional `claude-bun-bfs-runtime-source.yml` profile admits the exact C-only
archives from run 38991059015. It rehashes the entire package and checks the
compiler image, portable sysroot, original version bytes, 29 source objects and
four zero-file-budget host controls. Only the main symbol is renamed; the
original main text is unchanged. The Bfs and Oniguruma archives are linked
directly after the Rust objects, using Bun's existing compatibility wrappers
and the original's POSIX timer library. No separate Rust std archive or payload
file is used. This profile adds exact Bfs version/name/regex engine controls;
passing standalone hosts or applying its patch does not establish successful
Bun integration. Run 38992912659 completed both full-engine builds and all
24 Bfs-profile controls; independent readback and the allocator repair still
precede any complete-client admission. Ugrep, the private Bun revision,
other native platforms and complete client acceptance remain open.
