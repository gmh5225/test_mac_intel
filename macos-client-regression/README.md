# Whole-suite Mac regression publication

`run.py` runs the existing native source-client suite with all intermediate
observations staged in a private directory. Public records are copied only
after the complete 84-comparison host suite succeeds. Failed execution streams
are exported only through the existing authenticated CMS recipient. Cancellation
never publishes the private staging directory. Original inputs, client binaries
and plaintext failures are never copied to the artifact directory.

An authored envelope preflight runs before the legacy driver starts. The
negative publication control uses four copies of a self-authored failure
canary and verifies that none appears in public plaintext while all four
survive authenticated local decryption.
