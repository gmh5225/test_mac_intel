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
