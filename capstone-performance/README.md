# Independent Intel decoder measurements

The `Capstone fixed CPU performance control` workflow is a second environment
control on x86-64 Linux. It pins the measurement parent and all child processes
to the first CPU in the job's allowed CPU set, recording the original and effective
affinity. Its fixed A/A panel targets 500 ms CPU per observation, and the screen
targets 200 ms. It tests whether an affinity-constrained environment gives more
stable observations; it does not replace or discard the first Intel macOS run.
The first Intel macOS run did not establish stable A/A measurements.
The Linux port only guards Darwin QoS setup, selects ELF shared-library names,
and treats unavailable `RTLD_FIRST` as zero. The measured decoder loops and the
iced adapter are unchanged. Compilation is outside the pinned measurement phase.

Run the `Capstone independent Intel performance` workflow. It builds the pinned
NeverSight Capstone and iced forks from source on a native Intel macOS runner.
The experimental PPC patch is **not a qualified product change**: it passed local
native semantic checks but failed a repeated RISC-V throughput control on an
Apple M4. A different host supplies independent evidence, not a replacement for
that failure. Nothing in this workflow updates Capstone `next` or NeverD `dev`.

`manifest.json` records source revisions, source lineage and public input hashes.
The x86 consumer preserves the R145 Capstone loop and iced adapter, removing only
unused Zydis/XED implementations and setup. The other-ISA consumer is the frozen
R179 public API workload. Compiler and binary hashes are recorded on the runner.
The removed implementations change executable layout; compare A/B on this host,
not absolute times against earlier M4 results. Capstone setup remains inside the
x86 timed function; iced formatter/factory setup remains outside, as in R145.
Both setups are reused across each corpus pass within one timed sample. The
ordinary IntelFormatter and InstructionInfoFactory are used, not FastFormatter.

The benchmark includes scan, format, and format plus details/register access.
These APIs expose different metadata. Counts and boundary hashes must agree for
cross-decoder comparisons; their value hashes need only agree within a decoder.
Traversal checks are not a full semantic oracle. The PPC alias oracle and custom
formatter callback checks run separately before any measurement.

The fixed A/A panel runs first. The paired screen uses duplicate observations of
each binary with a balanced Williams order, CPU and wall time, fixed repetitions
per case, and no discarded observations. Controls that fluctuate or regress are
reported, never normalized away. A/A failures prevent qualification claims but
do not suppress exploratory results. Build, verification, timing, and cleanup
are sequential. There is no retry-until-faster loop or automatic promotion.

Only public digest-pinned binaries and generated fixture sources are used.
Downloaded binaries are read as data and never executed. Artifacts contain raw
JSON samples, commands, logs, host metadata, output hashes, source/build hashes,
and a cleanup receipt. Disposable clones, builds and corpus files are removed
after the run; evidence has a 14-day artifact retention period.

Local commands on an Intel Mac, from repository root:

```sh
python3 -m unittest discover -s capstone-performance -p 'test_*.py' -v
python3 capstone-performance/run.py prepare
python3 capstone-performance/run.py measure
python3 capstone-performance/run.py finish
```

Original harnesses and fixtures: Copyright (C) 2026 NeverD contributors,
<https://github.com/NeverSight/NeverD>, AGPL-3.0-only; see `LICENSE`. The Capstone
patch retains Capstone's existing BSD/LLVM file notices and is applied to that
source tree only. Public input binaries are downloaded from their publishers;
no binary corpus is redistributed in this repository.
