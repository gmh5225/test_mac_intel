# Additional native component candidates

`build_linux.py` builds Ugrep 7.8.4 and bfs 4.1.1 from hash-pinned public
archives on native Linux x64/ARM64. It builds their compression/regex libraries
in a private prefix, links static Ugrep and libc-linked Bfs, runs upstream checks and ten
authored controls, and retains sources and compiler identities. No captured
client or original prefix is executed by this component builder.

The selected transitive library versions are candidates. Their exact identity
in the original clients has not been established. Original comparisons and
integration into the reconstructed dispatcher are separate required steps.
Zstd has authored compression/decompression coverage; its upstream test suite
is not run. The native runner toolchain identity is retained, not asserted to
be a portable or reproducible compiler distribution.

The x64 static-glibc Bfs candidate crashes inside a dynamically loaded
libnss_systemd account lookup. Bfs therefore uses the host C runtime, matching
its NSS modules, while retaining the private static Oniguruma library. Its
measured glibc requirement is recorded separately; the original glibc 2.17
floor is not established by this standalone candidate. No system NSS policy or
upstream test exclusion is changed to admit a binary.

Real original-role comparisons require SSE2 on Linux x64 Ugrep and NEON on
ARM64. The earlier x64 no-SSE2 candidate fails exact version correspondence and
is retained as a refused profile. Bfs's original version output also exposes
its Clang 23/sysroot build and three compatibility poison macros; reproducing
that portable build context remains open. Version differences are preserved
as failures rather than rewritten or normalized.
