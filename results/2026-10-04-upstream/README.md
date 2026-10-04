# Independent upstream Intel HVF evidence — 2026-10-04

[Machine-readable results](summary.json) · [Interpretation in English, 简体中文, 繁體中文, 日本語, 한국어, Français, Deutsch, Español, Italiano, Русский and العربية](../2026-10-04-investigation.md).

The upstream [hvf-edge-cases](https://gitlab.com/pmdj/hvf-edge-cases) source and Makefile are unchanged at `f150b38bfff419fe19907b7a6a2d743a63b46a49`. Each run directory preserves its BSD license, source/binary hashes, observer plan, original log, child status/retirement, controller status, host observations, independently reconciled audit, GitHub artifact digests and extracted-file hashes. Earlier failures remain included.

| Image | Observer limit | Native elapsed | Result | Preserved witness | Run |
| --- | ---: | ---: | --- | --- | --- |
| macOS 15 Intel | 300 s | 300.022 s | timeout, child retired | checkpoints 0–70000; no final summary | [37193091543](https://github.com/gmh5225/test_mac_intel/actions/runs/37193091543) |
| macOS 26 Intel | 300 s | 300.030 s | timeout, child retired | checkpoints 0–90000; no final summary | [37193139264](https://github.com/gmh5225/test_mac_intel/actions/runs/37193139264) |
| macOS 15 Intel | 900 s | 361.960 s | exit 0, child retired | all checkpoints, guest Done, 100000-attempt summary | [37193853811](https://github.com/gmh5225/test_mac_intel/actions/runs/37193853811) |
| macOS 26 Intel | 900 s | 397.774 s | exit 0, child retired | all checkpoints, guest Done, 100000-attempt summary | [37193945642](https://github.com/gmh5225/test_mac_intel/actions/runs/37193945642) |

The 900-second runs were new attempts with a fixed limit, not extensions of the earlier runs. The workload stayed unchanged; snapshot cadence also changed from 5 to 15 seconds. All four runners remained reachable for final evidence. The later successful runs had 24 and 27 digest-verified artifacts. Upstream counts random interrupt call attempts and ignores their return codes; attempts can coalesce and do not prove individual delivery. The program also has a completion race around its last interrupt, so a timeout alone is not an HVF fault. None of these controls establishes NeverD CPU/Darwin acceptance, long-mode semantics or performance.
