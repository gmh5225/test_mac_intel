# Native Apple arm64e environment

This workflow probes GitHub-hosted Apple Silicon macOS 26 and Xcode 27 images. The labels come from GitHub's current
[runner inventory](https://github.com/actions/runner-images/blob/main/README.md).
The repository name does not select Intel hardware for these jobs.

`Environment.def` pins the NeverD source and owns the runner list, commands,
deadlines and build location. Each runner first executes NeverD's shared
compiler-original four-key PAC gate and compact/DWARF C++ call/catch/cleanup
dylib controls through `dlopen`, matching the installed-image loader. Disabled PAC, unavailable arm64e execution, a missing marker or a
failed control stops the job before dependency downloads and building. Exit 2
from an unavailable probe is a failed qualification, not a successful skipped job.

Only a passing preflight permits a Release build with the configured LLVM r6
package. `scripts/build.py` owns compilation and dependency refresh. The verifier
checks signature parsing and real 4 KiB/16 KiB `codesign` page preservation,
then requires all sixteen registered native installation/publication cases to run, with no
skips: O0/O2, chained and migrated threaded inputs, compact/DWARF language records and relocated
original signed language frames, plus compact/DWARF publication through original entry addresses. It binds the source revision, fixture hashes,
preflight report and executed test binary. General whole-image publication stays
outside this qualification.

Every job uploads complete or failed diagnostics. Generated preflight executables
are journaled and removed by NeverD. The controller refuses an existing build
directory, preserves configuration diagnostics, and removes its own build on
completion or failure. It does not install another model or use model results as
native execution evidence.

No workflow changes boot policy, NVRAM or SIP, or reboots its host. On macOS
versions that reject non-platform arm64e preview executables, an administrator
must configure a dedicated compatible test host before native qualification can
pass. The workflow reports observed availability; hosted runner labels alone do
not prove PAC or signed-unwind support.

The macOS 15 runner rejected the arm64e preview executable before entry. Newer
runners execute PAC, but the compiler-original executable with static B-key
fixups fails during startup; the equivalent `dlopen` library passes. Startup
loading uses a separate explicit userspace-fixup prerequisite. The controller runs
`probe-startup --startup-fixups userspace` before acquiring build inputs. This
SDK-derived process sandbox denies `map_with_linking_np`, causing dyld to apply
fixups in userspace; all four PAC keys retain their valid/corrupt controls. The
report binds both prerequisites and native publication to the same source SHA.
Default system startup still fails and is not reported as qualified.

A separate macOS 15 producer compiles the four original threaded dylibs with its
real `ld-classic`. It does not execute arm64e. The native jobs download those
owned test images and verify their source revision, source hashes and exact
binary hashes before running the same installation matrix. New replacement
objects and execution controls still come from each execution host's compiler.
No Apple linker binaries are uploaded. A missing legacy linker fails the
producer, and a missing or changed artifact fails qualification.

The Xcode 27 diagnostic found the same lost authenticated import addend in a
NeverD-installed threaded image and an unmodified `ld-classic` control. The
native matrix explicitly converts legacy inputs to modern chained metadata
before final signing; it does not claim unchanged threaded-output support on
that runner. Original threaded encoding remains covered by offline tests.
