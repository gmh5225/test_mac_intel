# Additional native component candidates

`build_linux.py` builds Ugrep 7.8.4 and bfs 4.1.1 from hash-pinned public
archives on native Linux x64/ARM64. It builds their compression/regex libraries
in a private prefix, links static ELF programs, runs upstream checks and ten
authored controls, and retains sources and compiler identities. No captured
client or original prefix is executed by this component builder.

The selected transitive library versions are candidates. Their exact identity
in the original clients has not been established. Original comparisons and
integration into the reconstructed dispatcher are separate required steps.
Zstd has authored compression/decompression coverage; its upstream test suite
is not run. The native runner toolchain identity is retained, not asserted to
be a portable or reproducible compiler distribution.
