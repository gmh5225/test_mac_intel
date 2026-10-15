# NeverD hosted 32-bit availability

This independent workflow inventories whether the available hosted machines can
help with Linux ARM32, PE ARM32, macOS i386, iOS ARMv7 and watchOS ARMv7k runtime
qualification. It does not resume the suspended Intel HVF workflows.

The native host first compiles and executes a small control program three times.
Linux ARM64 then tries real static ARM/Thumb ELF programs directly, recording
registered binary-format handlers. Windows ARM64 queries the OS architecture
APIs and tries a freshly compiled ARMNT executable. Intel macOS records Xcode,
SDKs and devices and attempts to link each legacy Apple target. The harness
retains compiler errors, process errors, host identity, binary hashes and the
exact workflow commit. No emulator is installed or selected by the workflow.

**A successful inventory job means its observations were collected. It does not
mean a 32-bit target passed native qualification.** Every report explicitly
records zero qualified patch observations. A tiny program executing on a
different host architecture is at most a compatibility candidate; it is not a
complete source-patch suite, a native ARM32 host or a physical Apple device.
Unavailable prerequisites remain unavailable. No test is skipped to declare a
target qualified. NeverC is neither checked out nor built or changed.

NeverD's previous qualification is pinned to
`fcee81c9a5e2f20a71090ade23ae833175f64c59`; the inventory's own commit is separate.
An execution-capable environment must subsequently run the complete authenticated
patch inventory before its evidence can be added to NeverD's coverage table.

Official platform references:

- [GitHub-hosted runner architectures](https://docs.github.com/en/actions/reference/runners/github-hosted-runners)
- [Apple's macOS 32-bit compatibility boundary](https://support.apple.com/en-us/103076)
- [Apple's Xcode support table](https://developer.apple.com/xcode/system-requirements)
- [Windows guest architecture query](https://learn.microsoft.com/en-us/windows/win32/api/wow64apiset/nf-wow64apiset-iswow64guestmachinesupported)

中文：此工作流只检查现有 Actions 环境能否执行相应的 32 位程序。绿色状态仅代表环境记录完整，
不代表 NeverD 原生补丁验证通过。报告保留实际系统、架构、编译和运行错误，原生补丁观测数始终为零。
只有具备执行条件后，才能继续完整补丁用例。它不恢复已暂停的 Intel HVF 测试，也不构建或修改 NeverC。
