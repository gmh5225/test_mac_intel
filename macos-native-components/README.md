# Mach-O component verification

`macho_objects.py` compares little-endian x86_64 and ARM64 relocatable objects
before and after a specified symbol rename. It compares every section body
(including debug data), section attributes, typed symbols, ordered relocation
references, symbol-table partitions, indirect symbols, and supported link-edit
metadata. ARM64 addend relocations retain their numeric addend. Unsupported
load commands and malformed ranges fail explicitly.

An empty translation unit may omit the symbol table. Such an object must have
no relocation or dynamic-symbol references; its section bytes and metadata
still receive the same comparison. Owned ARM64/x64 controls and an actual
x64 7zip empty object pass, while 22 malformed or altered inputs are rejected.

This verifier accepts plain machine-code objects, not LLVM bitcode. It does not
by itself qualify a Ugrep build or a recovered client. The initial owned
controls use Apple Clang 17 and LLVM objcopy 18: three real C/assembly rewrites
pass, and 19 mutations of code, binding, descriptors, relocation targets,
addends, command types and file bounds are rejected. Full component builds
must retain both object graphs and rerun the comparison with their actual
toolchain.

`private_symbols.py` applies the private C namespace to fresh program objects
and dependency archives. Every rewritten object must pass that comparison;
archive member identities/order and the full external symbol set are also
checked. An owned graph containing C, C++, TLS and ARM64 explicit addends
passes through the real archive rewrite path. Injecting a code-byte change
inside that path is rejected before the graph can be accepted.

`build_ugrep.py` builds Ugrep 7.8.4 and six pinned source dependencies on native
macOS ARM64 or Intel. Apple Clang 17 emits plain machine-code objects against
the macOS 15.5 SDK, with a macOS 13.0 deployment floor. Hash-pinned LLVM 23
archive, symbol and object-copy tools come from the dated Rust distribution;
staging them never invokes rustup. The component's C++ headers come from the
same SDK used by the public Bun source baseline.

The producer checks the complete observed version banner, runs the upstream
suites, renames every component-defined C symbol into a private namespace,
and reruns Ugrep's suite using a fresh library host. Its owned runtime controls
also cover PCRE, gzip and an invalid regular expression under a zero file-size
budget. C++ names retain their SDK runtime ABI.

The outer engine link must retain compact unwind. Apple ld with
`-no_compact_unwind` discards the ARM64 exception control's only unwind table,
causing an otherwise caught exception to terminate the process. The component
host checks for `__unwind_info` and catches a real exception before proceeding.
The existing public engine baseline has not yet received that integration
patch. A source library does not establish recovered client acceptance or
prove the original transitive dependency versions.

`compare_ugrep.py` first verifies authored Seatbelt, argument transport and
output-budget controls. It then checks 13 exact native Ugrep comparisons
against the hash-pinned published original, including Unicode/newline paths,
stdin, invalid regex, PCRE and four compression formats. Only bounded
diagnostics are uploaded; captured executables and source stay outside the
artifact paths. Intel version comparisons use the same machine for both
programs because the upstream SSE2 banner depends on CPUID.

`build_bfs_cross.py` compiles Bfs 4.1.1 and Oniguruma with the pinned Linux
LLVM 23 image, the measured Darwin target flags, and its macOS 26.5 SDK path.
It exports a fully checked private Mach-O C graph and compiled upstream test
programs. `qualify_bfs_native.py` runs Oniguruma tests, Bfs unit tests, and the
eight upstream integration strategies before and after replacing Bfs with a
fresh library host. The workflow executes these on native ARM64 and Intel
macOS and then uses the same strict comparison runner for eight original Bfs
cases. Cross-build success alone does not qualify a native component.
