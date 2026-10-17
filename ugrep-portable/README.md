# Portable Ugrep direct-call library

This optional producer rebuilds Ugrep 7.8.4, PCRE2 10.45 and the same selected
compression sources used by the qualified original-role comparisons. It uses
the pinned native Bun Clang images and portable GNU sysroot. Only Ugrep's main
symbol is renamed; its main code bytes must remain unchanged. Both the original
program and a fresh direct-call library host run the upstream suite. The host
also has four controls with RLIMIT_FSIZE=0, including PCRE2 and gzip input.

The final ELF must meet the original GLIBC 2.17 floor and reproduce the complete
version bytes from the independently qualified original-role comparison.
Raw source archives, nine source objects, dependency archives, main code bytes,
the library host, raw controls and compiler identities are retained. The Zstd
upstream test suite is not run. Exact original dependency versions, Bun dispatch
integration and complete-client acceptance remain separate open requirements.
No captured client or source is executed or uploaded by this producer.

CI obtains the public source archives from the independently qualified component
producer 38986089116 and rechecks each original pinned hash before extraction.
It consumes six source tarballs from that package. All C/C++ objects and libraries
are freshly rebuilt; the package's candidate executables are not build inputs.

The static upstream executable retains all pthread objects: the pinned
libstdc++ uses weak condition-variable references, which otherwise do not select
their implementations from the focal pthread archive. A real threaded
condition-variable control and defined-symbol checks run before compilation.
The final library host retains its dynamic pthread dependency explicitly.
