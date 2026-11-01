# NSRange Block SDK declaration evidence

This independent collection branch contains one read-only job. It records the
exact compiler declaration of NSIndexSet.enumerateRangesUsingBlock: in macOS
arm64, iOS arm64, macOS x86_64 and iOS Simulator x86_64 SDK profiles. The
original 5046-method recovery goal needs this declaration and lifetime evidence
for an original NSRange block; this branch does not claim application recovery.

The collector parses the installed SDK AST, obtains the exact method encoding
with libclang, and compiles an authored block probe to LLVM IR. It preserves the
noescape attribute, exact block encoding, compiler invoke definition and input
header hashes. It retains the BOOL pointer encoding separately for every
profile. SDK headers are hashed, not copied. Missing, ambiguous, malformed or
incomplete observations fail clearly and retain their records.

It does not link or execute the probe, carry any WMF/application inputs, load or
execute a framework provider, boot Simulator, or change any runtime setting.
The only invoked tools are Python, xcrun SDK/compiler discovery and Clang static
compilation. Loading libclang provides compiler parsing only. The seven local
boundary tests and both installed macOS SDK architecture profiles passed before
publication. Other existing branches and the paused scheduled automation remain
unchanged. The user authorized this and follow-up static collections needed for
all 5046 methods in the standing approval of 2026-11-01.
