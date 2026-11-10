# Native Apple arm64e environment

This workflow probes GitHub-hosted Apple Silicon macOS 26 and Xcode 27 images. The labels come from GitHub's current
[runner inventory](https://github.com/actions/runner-images/blob/main/README.md).
The repository name does not select Intel hardware for these jobs.

`Environment.def` pins the NeverD and LLVM fork sources and owns the runner list, commands,
deadlines and build location. Each runner first executes NeverD's shared
compiler-original four-key PAC gate and compact/DWARF C++ call/catch/cleanup
dylib controls through `dlopen`, matching the installed-image loader. Disabled PAC, unavailable arm64e execution, a missing marker or a
failed control stops the job before dependency downloads and building. Exit 2
from an unavailable probe is a failed qualification, not a successful skipped job.

Only a passing preflight permits a Release build from the pinned LLVM fork
source. The controller verifies its checkout identity before configuration and
records it in the final report. NeverD's default prebuilt release remains r6;
this environment deliberately selects `NEVERD_LLVM_PREBUILT=OFF` to validate
the fork's Darwin signed-return CFI correction. `scripts/build.py` owns
compilation and dependency refresh. The verifier
checks signature parsing and real 4 KiB/16 KiB `codesign` page preservation,
then requires all twenty registered native installation/publication cases to run,
with no skips: O0/O2, chained and migrated threaded inputs, compact/DWARF language
records and relocated original signed language frames, plus compact/DWARF
publication through original entry addresses for both chained and migrated
threaded inputs. It binds the source revision, fixture hashes,
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
An unchanged compiler-original main with B-key chains remains a separate failing control; it is not silently retried or counted as qualified.

After the twenty dylib cases, `run-executable` requires four additional
O0/O2 compact/DWARF publication cases. Each runs its original main executable,
then the signed published main through the retained startup entry, including
new authenticated providers, RELRO, catches and cleanup. This stage re-derives
the SDK sandbox profile and requires the exact successful startup report.
The controller binds its result to that report's hash and the pinned source.
The separate `run-default-executable` stage then runs the same four publication
cases directly, using the successful system PAC/dylib control report. NeverD
prepares B-key chain pages before signing so default dyld can apply every key.
The controller requires `native_default_executable_publication_qualified`, the
system loader identity and the exact preflight hash. A userspace-profile result
cannot satisfy this gate. General lifted-image publication remains unqualified.

A separate macOS 15 producer compiles the four original threaded dylibs with its
real `ld-classic`. It does not execute arm64e. The native jobs download those
owned test images and verify their source revision, source hashes and exact
binary hashes before running the same installation matrix. New replacement
objects and execution controls still come from each execution host's compiler.
No Apple linker binaries are uploaded. A missing legacy linker fails the
producer, and a missing or changed artifact fails qualification.

The [cold source run](https://github.com/gmh5225/test_mac_intel/actions/runs/42694273043)
builds NeverD `3e5fb93c816902d4b9893c1a54ffb353e3e3f117` independently on both
native hosts. Each passes 33 signing tests, twenty dylib cases, four main cases
and both six-control prerequisites without failures or skips; both owned builds
are removed. The later loader-slot fix preserves dyld-owned zero slots in
main RELRO storage. Its [separate delivered-host replay](https://github.com/gmh5225/test_mac_intel/actions/runs/42704012121)
at `6eb5e0af5333e7419f402fa3704a6c2f523dcec9` passes all twenty dylib and four main
cases on each host. That follow-up is an immutable binary delivery, with its own
source/binary/report identities, rather than another cold source build.

The Xcode 27 diagnostic found the same lost authenticated import addend in a
NeverD-installed threaded image and an unmodified `ld-classic` control. The
native matrix explicitly converts legacy inputs to modern chained metadata
before final signing; it does not claim unchanged threaded-output support on
that runner. Original threaded encoding remains covered by offline tests.

The previous prebuilt profile needed a 50-minute build budget: a macOS 26 cold
build reached 1433 of 1435 actions at its former 40-minute deadline. The current
source profile also builds LLVM for X86, ARM and AArch64, so `Environment.def`
allows 150 minutes for compilation and 180 for the enclosing job. A timeout
still fails qualification and preserves diagnostics before removing the owned
build; the controller does not retry or substitute a prebuilt producer.

The [default-system publication replay](https://github.com/gmh5225/test_mac_intel/actions/runs/42746949630)
qualifies source `e5a0fddc68b2fd03c2f25445aca674cef32ab3e6`
on both hosts with 20 dylib, 4 userspace-main and 4 default-system-main cases
each, zero failures and zero skips. Both prerequisite profiles pass all six
controls. The default gate launches CTest directly and binds the system probe
hash. This replay uses one identified local Release/r6 binary; it is not a cold
source build. The temporary delivery and workflow are removed after preserving
source, binary and report hashes. Current native hosts are Apple M1 virtual
CPUs; the Xcode 27 host reports CPA and CPA2 absent. FVP success remains separate
from native Apple CPTA-on qualification.

The canonical-IR producer adds two independent four-case gates: generated dylib
publication and generated main-executable publication under the system loader.
They select the installed Clang 22 frontend explicitly, retain its version/hash,
and use the pinned LLVM fork through NeverD's MC object backend. The r6 producer
emits explicit generic RA-state CFI that fails native catch/cleanup on macOS 26;
NeverD rejects that incompatible classic arm64e object without publishing it.
The correction lives directly in the LLVM fork, with no assembly stripping or
NeverD build patch. Authentication recipes, new providers,
RELRO and signed language frames pass through the same transactional installer.
`Environment.def` owns both stage commands; the controller binds their reports
to the same source and system probe. Their separate qualification flags do not
qualify arbitrary lifted modules or native Apple CPTA-on.

The [LLVM fork correction](https://github.com/NeverSight/llvm-project/pull/8)
has merged. Its [independent native controls](https://github.com/gmh5225/test_mac_intel/actions/runs/42761893719)
pass all four O0/O2 compact/DWARF cases and all six preflight controls on each
host. These controls use Apple linking without NeverD installation; the source
profile above separately qualifies the generated-image publication pipeline.

The [generated-image cold source run](https://github.com/gmh5225/test_mac_intel/actions/runs/42762192123)
uses NeverD `eabb96c44b7abaac2f628851968c05a090de5b5d` and merged LLVM
`5676029e378c9e37adc16c8216a8e8453ffafcae`. Both hosts independently pass
36 native cases, 33 signing tests and both six-control prerequisites, with no
failures or skips. This includes all eight generated dylib/main cases with
Clang 22.1.8 as the explicit IR frontend. Source, compiler, test-binary, probe
and XML hashes were independently checked, and both owned builds were removed.
Both hosts report Apple M1 virtual CPUs; macOS 26 does not expose the CPA/CPA2
sysctls, while Xcode 27 reports both features as zero. Native CPTA-on remains
unqualified.

The [integrated source replay](https://github.com/gmh5225/test_mac_intel/actions/runs/42772199612)
uses the immutable local Release host from NeverD
`0d3511620291254bffcaa90a356870016f2741f4` with the same merged LLVM source.
Both native hosts pass all 36 execution cases and both six-control prerequisites,
with no failures or skips. Archive, manifest, source, binary, probe and runtime
XML hashes were independently checked. This delivery is separate from the
cold builds; its temporary workflows and draft-release assets are removed after
preserving evidence. The maintained source profile pins this tested implementation.
