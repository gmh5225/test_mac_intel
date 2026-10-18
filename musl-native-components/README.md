# Native musl source component graphs

`build.py --arch arm64|x64 --sdk /abs/admitted-sdk --output /abs/new-directory`
uses the same digest-pinned LLVM 23 compiler profiles as the Linux GNU source
engine and the independently qualified Alpine 3.23 SDK. Run it on the matching
native Linux architecture. Full SDK extraction requires a case-sensitive
filesystem.

Only public hash-pinned Ugrep 7.8.4, Bfs 4.1.1, Oniguruma 6.9.10, PCRE2 10.45
and compression source archives enter the build. Optional `--source-inputs`
accepts the same exact archives. PCRE2 JIT is disabled on ARM64 and enabled on
x64, matching observed original musl configurations. The x64 reference banner
was observed under emulation; its CPUID-dependent SSE2 text is not a native
acceptance claim. Exact original transitive dependency versions remain unproven.

The compiler container has no network, dropped capabilities and an unprivileged
owned identity. An exact musl loader and musl-specific search-path file allow
configure programs to execute without changing GNU build tools' library paths.
An authored condition-variable/thread program must execute with only musl libc
in `DT_NEEDED` before source tests run. The final source library hosts also use
static C++ and GCC support libraries.

Fresh compiler objects are retained before entry renaming and private C
namespacing. Every allocated/debug/group byte, typed symbol and relocation
referent is checked after the rename. C++ symbols keep their real runtime
identity. Both upstream executables and direct-call library hosts run upstream
checks; zstd's separate upstream suite is not run. The hosts have focused
zero-file-budget controls, including real C++ regex exceptions. These component
checks do not admit a complete Bun engine or a captured client.

No captured executable, prefix, JavaScript, or reconstructed client enters a
public artifact. Successful packages contain only public sources, authored
recipes, source libraries, and bounded authored diagnostic output.

PCRE2 `RunGrepTest` test 150 assumes that a `locale` command in `PATH` means
that its C runtime rejects `LC_CTYPE=locale.bad`. The GNU compiler image has
that command while the musl-linked CLI accepts the name. Both initial native
runs retained exactly this one output difference. A separately compiled target
C `setlocale` control and the unchanged PCRE2 CLI must demonstrate the actual
musl behavior before a hash-gated correction changes this single expected
result to no match (`RC=1`). The original test script, all other expected cases,
and the PCRE2 runtime implementation remain byte-identical; test 150 still
executes. The fixture patch and both controls are retained explicitly.

`build_runtime.py --arch arm64|x64 --sdk /abs/admitted-sdk --components
/abs/admitted-components --output /abs/new-directory` compiles public Bun
`c6da4a4d3010e5553438c60f6bd76d981976867c` with the independently admitted C
graphs, a fresh single Rust/std/rg graph, and the unchanged public Linux seccomp
source/filter. It restores the measured 29-name musl allocator export surface
through the existing public mimalloc implementations and retains static C++
exception support. The final engine must import only target musl libc and pass
19 authored role/JavaScript controls plus 768 filename/inherited-FD controls.
This is a producer gate; complete-engine admission and captured-client
correspondence remain separate requirements.

The allocator implementation remains the public Bun-pinned
[mimalloc override source](https://github.com/oven-sh/mimalloc/blob/92ef6587c57b262f6e6abf513f7776a2f8d12aeb/src/alloc-override.c).
The seccomp source is hash-pinned to sandbox-runtime
`9520430507ce3c354a71b1518e29e76121407ed1`; its Apache-2.0 license is downloaded
with the source. The generated filter header is byte-identical to the earlier
independently verified public libseccomp filter graph.
