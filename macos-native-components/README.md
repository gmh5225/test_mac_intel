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
x64 7zip empty object pass. Data-in-code entries in MH_OBJECT use section VM
addresses, as emitted by [LLVM's MachObjectWriter](https://github.com/llvm/llvm-project/blob/llvmorg-23.1.1/llvm/lib/MC/MachObjectWriter.cpp#L966-L980); their ranges, lengths and
types are verified too. Seven real renames pass and 32 malformed or altered
inputs are rejected.

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

`ugrep-library-pins.json` admits producer 39038017210 after both native jobs
and independent artifact/raw-output verification: 146 objects per architecture
and 26 exact original-role pairs in total. It admits only the component
libraries, not a reconstructed full engine or client.

`build_bfs_cross.py` compiles Bfs 4.1.1 and Oniguruma with the pinned Linux
LLVM 23 image and the measured Darwin target flags. `prepare_sdk.py` downloads
the macOS 26.5 SDK from Apple's CDN, checks its pinned whole-package SHA-256
and catalog XAR-TOC digest, and extracts it offline with hash-pinned upstream
xmac. The SDK is mounted at the measured path and is not uploaded. The input
package's Apple Software signature was also verified during qualification.
It exports a fully checked private Mach-O C graph and compiled upstream test
programs. `qualify_bfs_native.py` runs Oniguruma tests, Bfs unit tests, and the
eight upstream integration strategies before and after replacing Bfs with a
fresh library host. The workflow executes these on native ARM64 and Intel
macOS and then uses the same strict comparison runner for eight original Bfs
cases plus an explicit execdir boundary. Cross-build success alone does not
qualify a native component.

The original Bfs uses `posix_spawn_file_actions_addfchdir`, introduced in macOS
26.0, despite declaring a macOS 13.0 deployment floor. On macOS 15, both the
captured original and the fresh source host fault at that missing weak import
for execdir. The complete upstream suites therefore run on native macOS 26;
separate native macOS 15 jobs retain exact ordinary-role comparisons and the
same observed execdir fault. Earlier upstream failures are retained. No version
output or runtime failure is rewritten to hide this platform boundary.

`bfs-library-pins.json` admits producer 39039756810 after independent checks of
77 objects per architecture, all 32 upstream integration runs, 14 Oniguruma
executions and 36 raw original-role pairs across macOS 15/26. The complete
upstream suite needs macOS 26. The original macOS 15 execdir fault remains an
explicit compatibility boundary.

`build_runtime.py` adds a native-source profile to the existing public macOS
builder. It uses the same pinned LLVM 23/Rust toolchain and the qualified
component archives. The locked Rust/std/rg graph is shared with the Linux
recipe; six existing Linux source-patch profiles and their receipts remain
byte-identical after this extraction. New Mac builds prepare public rg/PCRE2
sources directly and consume no compiled Rust input.

The profile links a separate, accepted pre-namespace PCRE2 C archive for rg,
uses the pinned SDK 26.5 explicitly on both targets, preserves final exception
sections, and allows/requires precisely the six observed Ugrep exception
imports. The six observed Ugrep/RE-flex initializer names are explicit too.
Other forbidden imports and binary checks stay active. The real component
host passes this verifier; five altered expectations are rejected.

The new full-engine workflow checks ARM64 and x64 on native macOS 15 and 26,
including 768 actual rg filename/inherited-FD controls per host. Source build
and native control success still need independent qualification and actual
recovered-client comparisons; adding this recipe does not admit a complete
recovered macOS client.
