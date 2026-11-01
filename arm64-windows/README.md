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

No private driver or game sample is included. The source checkout and its
license remain separate from this harness.
