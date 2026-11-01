# NeverD Windows ARM64 qualification

This bounded workflow checks the public NeverD source at
`1653e4cfaaf5b9f9138c99750aa7984933f2cc2d` on `windows-11-arm`.
The Python process must report a native ARM64 host before any execution is
counted. Each run retains the exact source and harness revisions, host details,
compiler commands and raw observations.

The original-code leg runs the existing caller-context, cross-page memory-write
and exclusive-instruction oracles. Validator unit tests check the observation
format before the native probes run. These are actual Windows ARM64 process
executions; they do not load a Windows kernel driver and do not by themselves
validate recovered C, the NeverD emulator, or every Windows API.

The recovered-C job runs on both native Windows ARM64 and Windows x64. Its
payload records the exact NeverD source commit, engine hashes, original
Microsoft SDK/WDK fixture objects and every generated source hash. It relinks
those original objects and compiles HighC/LLVMC at O0 and O2, then compares:

- All fourteen D3DCompile2 arguments, including independent nonzero values in
  the secondary-data and trailing stack positions. A retained pre-fix LLVMC
  negative control must lose those arguments; it cannot count as a success.
- Real WindowsCreateString UTF-16 contents, lengths and cleanup, and real
  PathCchCombineEx success/error results and complete output buffers.
- NDIS open/read/close success and failure paths, SD Port's byte-width offset
  and bounded writes, PortCls's native callback, and Stream Class's void call.

Driver APIs and D3DCompile2 use explicit observable ABI models in `provider.c`.
The driver functions execute as native user-process DLL functions relinked
from the original objects. This is a value/call-projection test, not kernel
driver loading or validation of those kernel API implementations. The LLVMC
image-storage declarations are initialized from the original fixture image
with imports resolved to the same models or real Windows DLLs; source reads
are retained. The generated C is not edited to remove reads or fill arguments.

`payload/*/manifest.json` identifies the exact captured source and original
fixture hashes. Source fixtures and NeverD's license are available in the
pinned NeverSight/NeverD repository; the original fixture sources are also
retained beside their objects. The workflow uses the native target Python
architecture and rejects mismatching PE machine types before executing a DLL.

No private driver or game sample is included. The source checkout and its
license remain separate from this harness.
