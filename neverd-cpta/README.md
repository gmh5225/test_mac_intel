# Controlled CPA2 execution environment

This separate manual/branch workflow develops NeverD's arm64e.x1 validation
environment. It runs the **official Arm AEM FVP 11.32.19 on x86-64 Linux**;
the repository name does not imply an Intel Mac can execute arm64e natively.
Existing suspended Intel HVF workflows remain suspended.

The archive is downloaded directly from Arm and checked against a pinned
SHA-256. Its published MD5 was independently checked when pinning the package.
The workflow installs the unmodified package under its included Arm terms;
the model and its libraries are not redistributed in the artifacts.
Semihosting is enabled at the model root. The bare EL1 guest disables the
board TZC gate with `bp.secure_memory=0`; it does not install secure firmware
or claim to validate that controller.

The bare-metal guest requires EL1 as the highest implemented exception level,
reads `ID_AA64ISAR3_EL1.CPA`, and requires the actual value 2. With no EL2/EL3
there are no higher-level SCTLR2 enable gates. It writes and reads back all
four `SCTLR2_EL1.CPTA/CPTA0` combinations (values 0, 512, 1024 and 1536).
Concrete EL1 ADDPT overflow/underflow results must follow CPTA independently
of CPTA0. No ID register or result is fabricated.
It also executes GPR/SIMD register-offset memory controls and the same aligned
or eight-byte-misaligned address through SP and X0 with `SCTLR_EL1.SA` off/on.

The MMU maps the first two MiB of guest DRAM with 4-KiB Normal WB pages.
Code is privileged; data is writable at EL0/EL1 and non-executable. A common
EL0-writable mapping cannot execute at EL1, and disabling the MMU would make
unaligned Device-memory accesses fault. MAIR, TCR, TTBR and SCTLR readbacks,
PAN=0 and UAO=0 are required. The linker rejects guests exceeding the mapping.

`run.py --el0-control` additionally enters EL0t with ERET and executes real
GPR/SIMD memory controls under every CPTA/CPTA0 combination. This profile
shares read-only executable code with EL1 while retaining writable,
non-executable data. Its returning SVC must have the exact site and immediate;
the hardware-saved `SPSR_EL1.M` must identify EL0t. Every mode reports that
origin and its memory result. All 82 checks are mandatory. Actions runs this
profile separately from the original 74-check EL1 environment, preserving
independent artifacts. The EL0 control does not execute NeverD output.

All 74 checks, four modes, explicit guest completion and a successful process
exit are required. Missing features, exceptions, timeouts, malformed or
incomplete records fail the job. Artifacts preserve the exact commands,
source/guest hashes, model version/parameter listing and raw transcript.

The original EL1 profile is **model validation of the environment**. It does
not qualify Apple silicon, EL0 instruction execution, memory overflow/other translation faults,
CPACHECK choices or
NeverD's emitted code. Those require further fixtures in this environment.
The JSON report explicitly retains these limits even when all controls pass.

Local cross-compilation without a model:

```sh
python3 neverd-cpta/run.py --build-only --compiler clang --linker ld.lld
```

Definitions, encodings, configuration values and pinned downloads belong in
`CptaGuest.def` and `CptaEnvironment.def`.

`generated_memory.py` consumes actual exports from NeverD's
`AArch64ImmediateMemory` suite. Require all eight named tests to complete with
an artifact export, then pass its four files, the test JSON and the exact
NeverD commit. Inputs and hashes are preserved before compilation:

```sh
python3 neverd-cpta/generated_memory.py \
  --artifacts /path/to/immediate-memory-export \
  --test-report /path/to/immediate-tests.json \
  --neverd-revision FULL_40_CHARACTER_COMMIT
```

Each of five routes (HighC and LLVMC at O0/O2, plus the actual LLVM ELF object)
executes 177 samples under every control combination and requires 79 checks.
The original generated functions/object stay unchanged; the independent
harness entry is renamed and exposes its actual array size. Only unused
formal-parameter warnings are suppressed for the fixed-ABI generated C.
The model archive, capability/completion gates and 45-second process limit
remain the same. The default workflow qualifies the two environments; running
this separate matrix qualifies only its declared explicit-IR inputs.

This is no-image, nonoverflow, normal-memory model coverage. Automatic
lifting, image rebasing/relocation, original SP, writeback/pairs, native
half/whole-vector ABI, EL0 instruction execution and Apple hardware remain
outside its scope. Even a passing matrix keeps the broad
`neverd_output_qualified` and `native_apple_cpta_qualified` fields false; only
`explicit_immediate_memory_output_qualified` is granted per passing route.
`CptaGeneratedMemory.def` owns the matrix inventory, required test identities,
source bridge, flags and expected observations.

`--profile image` instead requires the distinct
`cpta_image_memory_artifacts` export from that same eight-test report. These
177 functions were emitted with a Mach-O image context but use explicit runtime
GPR parameters, including scalar SSA arithmetic. It grants only
`explicit_image_context_runtime_memory_output_qualified`; it does not qualify
image-derived addresses or relocation. `--profile el0-image` uses the same
export at EL0 and additionally checks hardware exception origin under every
control combination. Its separate key is
`explicit_el0_image_context_runtime_memory_output_qualified`.

`--profile image-relocated` requires the separate
`cpta_relocated_memory_artifacts` export. Its 177 cases use image-owned base
addresses, alternating direct occurrences and SSA COPY. An independent getter
must alias the same complete storage as every original access. This proves
nonoverflow rebasing for these explicit fixtures, including negative and maximum
Q displacements, without qualifying an entire automatically lifted program.
`--profile el0-image-relocated` executes that same export through the EL0 entry
and origin checks. Both profiles retain the five unchanged C/object routes,
all four effective controls and the complete eight-test input gate.

`--profile el0-immediate` executes the original 177-sample export at EL0;
`--profile el0-register` uses the seven-test SP report and its matching
`cpta_register_memory_artifacts` export for all 184 GPR/SIMD register-offset
samples. Each profile requires 83 checks on every source/object route,
including the actual EL0t origin under all four control combinations. Their
qualification keys are `explicit_el0_immediate_memory_output_qualified` and
`explicit_el0_register_memory_output_qualified`. They do not qualify literal
SP access at EL0, overflowing memory, tagging, image rebasing, automatic
immediate lifting, every internal CPACHECK choice or Apple hardware. The
default Actions matrix validates the two environments; these separate
generated-output matrices still require actual NeverD exports.

Use `--profile stack` with the separate seven-test
`AArch64StackAddressMemory` report and its `cpta_stack_memory_artifacts`
export to check actual explicit raw-SP output. This profile requires 177
immediate samples, all four effective CPTA/CPTA0 values and a separate
`SCTLR_EL1.SA=1` readback in every mode: 83 mandatory guest checks per route.
It grants only `explicit_raw_sp_memory_output_qualified`. All original
functions and the LLVM ELF object remain unchanged. Native SP exception and
GPR-control checks use NeverD's `scripts/verify_arm64e_sp_memory.py` with its
actual C and Mach-O exports; they do not establish Apple CPA2 execution.
Use `--profile stack-register` with the same complete seven-test SP report
and its `cpta_stack_register_memory_artifacts` export to require all 184
register-offset GPR/SIMD samples, including every extension and scale. It
requires the same 83 checks and grants only
`explicit_raw_sp_register_memory_output_qualified`. The matching GPR export
`cpta_register_memory_artifacts` uses `--profile register`, requiring 79
checks and granting only `explicit_register_memory_output_qualified`.
NeverD's native verifier uses `--profile register` with those two exports
and the SP report for both report arguments; all 184 SP faults and every
matching GPR result must pass independently.
Reconstructed frames, image-backed SP, stack ABI, tagging and asynchronous
unwind remain outside this profile's scope. The default workflow still runs
the environment profile; it does not claim the separate output matrix ran.

References:

- [Arm Architecture FVP downloads](https://support.arm.com/tools-and-software/fixed-virtual-platforms/arm-architecture-fvps)
- [Arm A-profile feature definitions, 2025-09](https://documentation-service.arm.com/static/68da532186b96e39e38c318c)
- [Linux system register metadata](https://github.com/torvalds/linux/blob/master/arch/arm64/tools/sysreg)
- [Arm memory management](https://developer.arm.com/documentation/101811/latest)
- [Arm exception model](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Learn%20the%20Architecture/Exception%20model.pdf)
- [Arm execution permissions](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Learn%20the%20Architecture/Providing%20protection%20for%20complex%20software.pdf)

The `writeback` and `el0-writeback` profiles require the separate eight-test
`AArch64WritebackMemory` report and its
`arm64e_writeback_memory_artifact_directory` export. They execute 130 independently
assembled GPR single pre/post-index samples through the same five output routes,
comparing load values, completed bases and every buffer byte against original
register encodings. All four CPTA/CPTA0 combinations remain mandatory; EL0 also
requires every hardware-origin check. This bounds nonoverflow Normal WB memory
only. It does not qualify automatic whole images, image relocation, SP/stack
ABI, SIMD/pairs, overflow/tagging environments or native Apple CPA2 hardware.

The `vector-writeback` and `el0-vector-writeback` profiles require the distinct
ten-test `AArch64VectorWritebackMemory` report and exactly one
`arm64e_vector_writeback_memory_artifact_directory` export. The 100 independent
B/H/S/D/Q single pre/post-index samples compare the complete V value, completed
base and every buffer byte against original-register native instructions. The
same five output routes, four CPTA/CPTA0 settings and EL0 origin checks apply.
These profiles retain the bounded Normal WB, nonoverflow scope; automatic whole
images, image relocation, original SP/stack ABI, pairs, tagging, foreign exception
identity and native Apple CPA2 hardware remain unqualified.

The `pair` and `el0-pair` profiles require the distinct ten-test
`AArch64PairMemory` report and exactly one
`arm64e_pair_memory_artifact_directory` export. They execute 215 independent
GPR W/X, LDPSW and SIMD S/D/Q pairs, covering non-temporal, offset, pre-index
and post-index forms with signed imm7 boundary samples. Both complete values,
the completed base and all 4096 buffer bytes are compared with independent
original-register instructions. Five output routes, all four CPTA/CPTA0
settings and every EL0 origin gate remain mandatory. These profiles qualify
only the declared Normal WB nonoverflow integer bridges; automatic whole
images, image relocation, original SP/stack ABI, overflow/tagging, native vector
ABI, foreign exception identity and Apple CPA2 hardware remain unqualified.

Generated output is compiled unchanged. The environment supplies freestanding
`string.h` declarations from `CptaGeneratedMemory.def`, since the bare-metal
Clang target has no system C library headers. The generated header hash is
recorded alongside source provenance. These declarations supply no library
implementation and do not replace any instruction or output operation.
