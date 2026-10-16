# Direct native component linkage candidates

The first source-engine client run exposed a real incompatibility: embedded ELF
payload writes exceed the existing 256 KiB file limit during actual Bash. These
new candidates link the public Rust ripgrep and C seccomp implementation into a
host that already has a Rust global allocator, without writing an ELF at entry.
Seven public controls run with RLIMIT_FSIZE=0 before any full Bun integration.

The compiler is Bun's pinned nightly-2026-09-15. Public archives, crate checksums,
the PCRE2 version-reporting overlay and selected source inputs are retained.
Cargo uses an exact local vendor tree offline. The original ripgrep main body
is copied unchanged into a library source with a C ABI entry that delegates to
the nightly ExitCode::exit_process method; no opaque exit-code representation
is inferred. See https://doc.rust-lang.org/nightly/std/process/struct.ExitCode.html.

The seccomp C source and generated filter header remain byte-identical to their
separately verified public inputs. Bun must compile that C source with its own
portable flags, link the Rust archives, then pass its glibc gate and complete
actual-client acceptance. A successful standalone host does not establish those
later steps, recover private producer types or restore the original Bun revision.
