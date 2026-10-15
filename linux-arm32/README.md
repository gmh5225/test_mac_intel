# Direct Linux ARM32 compatibility qualification

The availability run found that the hosted ARM64 Linux machine executes ARM and
Thumb code directly. This workflow runs the complete authenticated 32-image,
96-observation NeverD suite through the Linux kernel and installed ARM32 glibc
loader. The execution classification is **compatibility on ARM64**, not a native
32-bit host or QEMU. No explicit loader command or emulator is used.

The fixture bytes, 30 publication receipts and case definitions are pinned to
NeverD `fcee81c9a5e2f20a71090ade23ae833175f64c59`. The original input archive is
the already audited artifact `11966718331` from
[run 38694434082](https://github.com/NeverSight/NeverD/actions/runs/38694434082).
Its old QEMU logs remain inside that original input archive for provenance;
none are copied into the new execution output. Every new observation runs a
process three times and records the new harness commit and run separately.

The runner checks matching `binfmt_misc` rules before execution and rejects
possible interpreter substitution, including masked magic and extension rules.
It verifies all image hashes and ELF interpreters, records the installed glibc
loader hash, and checks images, loader and handlers again after all executions.
Wrong results, missing tools, malformed inputs or incomplete inventories fail.

This workflow checks out NeverD's pinned scripts without submodules. It never
checks out, builds, executes or changes NeverC. It does not claim PE ARM32 or
legacy Apple hardware coverage.

中文：本任务在 ARM64 Linux 主机上直接运行全部 ARM/Thumb 补丁用例，记录为兼容模式。
它验证内核及 glibc 加载路径，不是原生 32 位主机或 QEMU 验证。所有 32 个镜像和 96 次运行
均需完整通过；输入与当前测试脚本分别保留提交号。NeverC 不会被检出、构建、执行或修改。
