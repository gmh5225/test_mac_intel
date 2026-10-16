# Native Bun reconstruction

The pinned public source is Bun
[`c6da4a4d3010e5553438c60f6bd76d981976867c`](https://github.com/oven-sh/bun/commit/c6da4a4d3010e5553438c60f6bd76d981976867c).
The original client reports a different revision, `eecfd55deb`; this project
does not claim to have recovered that unpublished source revision.

`role_contract.rs` reconstructs the observed Linux selector: exact raw ARGV0
spelling, unconditional consumption of that variable when present, and
recognized actual argv[0] basename precedence. The four role values are rg,
ug/ugrep, bfs and apply-seccomp. Its Rust type names are authored.

`patch_bun.py` requires the exact public process-entry hash before changing
one boundary. `recovered_multicall.rs` runs there before VM/thread setup and
embeds pinned, source-built Linux rg and apply-seccomp ELF payloads. It seals
an anonymous descriptor and replaces its own process image without a host
temporary pathname. This differs from the original static-library linkage.
Ugrep and bfs currently fail explicitly as unintegrated implementations.

The source workflow uses fresh Bun source/build/cache directories in pinned
native compiler containers. The containers supply toolchains; the engine's
core object files are rebuilt. JavaScriptCore may still be a pinned public
prebuilt dependency, as permitted by Bun's upstream build. Public binaries and
diagnostics are the only workflow artifacts. Captured clients and source are
never committed or uploaded.

A passing build and the eight public controls are prerequisites for later
captured-client graph rebuild, complete readback and original comparisons.
Neither a prepared patch nor these controls establish full recovery.
