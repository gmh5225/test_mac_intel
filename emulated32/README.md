# Legacy 32-bit source patch execution

These workflows measure real compiled C images and NeverD-patched images.
A successful Actions job must have every expected exit value, three separate
process launches per image, authenticated input hashes, and a complete report.
A missing executor or an unavailable API fails the job. Native hardware or
Apple/Microsoft OS coverage is never inferred from a green compatibility job.

| Runner path | Required observations | Meaning |
| --- | ---: | --- |
| QEMU TCG, complete Debian ARM32 kernel and userspace | 96 | ARM/Thumb Linux system emulation |
| ARM32 Wine inside that guest | 30 | PE ARMNT loader/API compatibility under emulation |
| Darling on Linux x86-64 | 30 | i386 Mach-O compatibility; not macOS |
| touchHLE on Intel macOS | 30 + 30 | ARMv7 and ARMv7k C code in an iOS HLE; not an Apple OS or watchOS runtime |

Every family checks original behavior (exit 9), nonleaf replacement (87),
writable pointer/state replacement (92), and floating-point/stack arguments
(93). New PE/Mach-O images cover source IR, source object, and supplied object.
The historical Linux images additionally cover GCC source and supplied object.
CPU architecture and case inventories are checked independently of manifests.

`linux-arm32/qualified-images.zip` pins the previously qualified NeverD
`fcee81c9a5e2f20a71090ade23ae833175f64c59` images. New image manifests separately
record the actual generator commit, engine source digest, binary hashes,
compiler version, and (for Mach-O) the linker source and alignment patch.
Neither result can be relabelled as a newer source revision.

## Reproduction

Build NeverD with its corrected LLVM source profile, without rebuilding
NeverC. Run `prepare_pe.py` and `prepare_apple.py` with `--repository`, `--build`
and a fresh `--output` directory on the documented macOS toolchain. Preparation
rejects uncommitted engine changes and preserves failed output directories.
The script compiler paths identify Clang/LLD 22; the manifests record versions.

For legacy Mach-O linking, build cctools-port commit
`904de2a71d4da6a9b30d2efaf912a10ddc7d9ddb` with the adjacent
`ld64-cfi-alignment.patch`, configure with `--disable-tapi-support
--disable-lto-support`, and install under `build-source-patch/cctools-install`.
The patch preserves larger requested CFI alignment. The real linked originals
reserve zero-filled capacity for exception metadata. NeverD's bounds, unwind,
and transactional publication checks remain enabled.

`link-only-libSystem.dylib` is a symbol interface built from the included C
stub solely for linking. It must never be installed in a runtime search path.
The i386 link reserves a 64 KiB page-zero segment so Darling can map it under
Linux's standard low-address protection. Darling or touchHLE supplies the actual exit implementation. No Apple SDK is
used to link these probes, and SDK qualification is explicitly false. Clang's
automatically selected host sysroot during header-free source compilation does
not constitute availability of an old Apple SDK. The ARMv7k probe uses an
ordinary C entry in an iPhone HLE bundle; it exercises neither WatchKit nor the
watchOS loader, signing, boot process, or device services.

Wine's first registry installation runs with the same ARM32 packages in a
chroot on the ARM64 host's kernel compatibility layer. Its separate 90-second
result is setup evidence and counts as zero patch observations. The prepared
registry is then placed in the guest; the guest still requires a successful
90-second Wine initialization and all 30 PE launches under its ARM32 kernel.

Darling and touchHLE archives are pinned by release and SHA256. Debian's actual
package versions, guest kernel/initrd hashes, QEMU command line, CPU state,
stdout/stderr and every return code are archived. Failed attempts remain
historical evidence rather than qualified runs. This workflow does not resume
the repository's unrelated suspended Intel HVF experiments.

See NOTICE, APPLE_LICENSE, and the root LICENSE for provenance and terms.
