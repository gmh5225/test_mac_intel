# Native x64 audio-integrated client acceptance

This owned workflow continues the sealed Linux audio client comparison on a
GitHub-hosted Ubuntu x64 runner. It admits the exact public GNU and musl source
engines, reconstructs the private module graph from hash-pinned public packages,
and substitutes only module 2364. Each preserved/readable client must match the
private sealed candidate's complete file size and SHA-256 before execution.

Two privately reconstructed audio modules and a small expected-hash manifest
arrive as 52 repository secrets. Four bounded batches avoid the host's process
environment limit. Neither captured JavaScript nor complete client binaries
are transferred through the repository or exported as workflow artifacts.

Owned kernel controls check both seccomp installation paths, exec inheritance,
invalid-filter rejection, and nested bubblewrap namespaces before any client
is mounted. Actual client runs retain the existing offline, read-only,
non-root boundaries, process/resource limits and product Bash sandbox. The
unchanged seven Bash and thirteen Grep/Glob scenarios compare both rebuilt
layouts with the original: 40 pairs for each libc, 80 in total. The retained
independent reader recomputes raw protocol, requests and workspace bytes.

Private diagnostic streams are bounded, indexed and encrypted using CMS
AES-256-GCM with the owner's RSA-4096 OAEP recipient. The uploaded artifact
contains only this opaque envelope and aggregate status. The private key is
never sent to the runner. The source engines remain public upstream builds;
this does not establish recovery of the erased private producer revision.
