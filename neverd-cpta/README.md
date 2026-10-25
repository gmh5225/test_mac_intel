# Controlled CPA2 execution environment

This separate manual/branch workflow develops NeverD's arm64e.x1 validation
environment. It runs the **official Arm AEM FVP 11.32.19 on x86-64 Linux**;
the repository name does not imply an Intel Mac can execute arm64e natively.
Existing suspended Intel HVF workflows remain suspended.

The archive is downloaded directly from Arm and checked against a pinned
SHA-256. Its published MD5 was independently checked when pinning the package.
The workflow installs the unmodified package under its included Arm terms;
the model and its libraries are not redistributed in the artifacts.

The bare-metal guest requires EL1 as the highest implemented exception level,
reads `ID_AA64ISAR3_EL1.CPA`, and requires the actual value 2. With no EL2/EL3
there are no higher-level SCTLR2 enable gates. It writes and reads back
`SCTLR2_EL1.CPTA` and requires concrete ADDPT overflow/underflow results to
change as expected between off and on. No ID register or result is fabricated.
It also executes GPR/SIMD register-offset memory controls and the same aligned
or eight-byte-misaligned address through SP and X0 with `SCTLR_EL1.SA` off/on.

All 36 checks, both modes, explicit guest completion and a successful process
exit are required. Missing features, exceptions, timeouts, malformed or
incomplete records fail the job. Artifacts preserve the exact commands,
source/guest hashes, model version/parameter listing and raw transcript.

This is **model validation of the environment**. It does not qualify Apple
silicon, EL0/CPTA0, memory overflow/translation faults, CPACHECK choices or
NeverD's emitted code. Those require further fixtures in this environment.
The JSON report explicitly retains these limits even when all controls pass.

Local cross-compilation without a model:

```sh
python3 neverd-cpta/run.py --build-only --compiler clang --linker ld.lld
```

Definitions, encodings, configuration values and pinned downloads belong in
`CptaGuest.def` and `CptaEnvironment.def`.

References:

- [Arm Architecture FVP downloads](https://support.arm.com/tools-and-software/fixed-virtual-platforms/arm-architecture-fvps)
- [Arm A-profile feature definitions, 2025-09](https://documentation-service.arm.com/static/68da532186b96e39e38c318c)
- [Linux system register metadata](https://github.com/torvalds/linux/blob/master/arch/arm64/tools/sysreg)
