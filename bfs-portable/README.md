# Bfs portability reconstruction

The original Bfs version output exposes Clang 23, a target-specific sysroot,
release configuration, Oniguruma paths and three compatibility poison macros.
This experiment compiles unchanged Bfs 4.1.1 and Oniguruma sources using those
measured compatibility choices, with the public Bun compiler image and pinned
focal/GCC-13 sysroot. It does not claim the original private sysroot bytes.

Both native architectures must build and pass the upstream Oniguruma/Bfs checks,
then independently pass a GLIBC_2.17 version-needs gate and account/file controls.
The compiler runs without network or capabilities as the owning non-root user.
A failing public candidate, full flags, symbols and logs are retained. Version
strings are emitted from the real build configuration and are not rewritten.
This is a standalone component experiment; static Bun linkage remains separate.

## Public Bun compatibility link

The public Bun revision `c6da4a4d3010e5553438c60f6bd76d981976867c`
wraps `fcntl64` and `statx` outside component compilation. The exact source,
link-flag source and upstream license are retained under `bun-compat-source`.
Only the two unchanged function ranges and their argument classifier are
compiled for this standalone outer link. No code is copied from glibc.

Bfs's measured flags are actual Make/compile inputs. Its generated version
output must be identical before and after the outer link. Native forwarding,
forced old-symbol fallback and all three fcntl argument classes receive
authored runtime controls before the complete upstream Bfs suite. The final
ELF must still require at most GLIBC_2.17. Bun's release section collection
removes unreachable C++ runtime functions; the actual Bfs link map is retained.
Complete version bytes must match the original measured profile, with no
normalization. The public source supplies a
reconstruction candidate; it does not prove the private original revision.
