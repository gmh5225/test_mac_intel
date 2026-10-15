# Native Windows recovery environment

The workflow qualifies Windows x64 and ARM64 hosts for the Claude Code 2.1.296
reconstruction effort. This first stage runs only authored fixtures and an
official Bun 1.4.3 runtime pinned by archive and executable SHA-256.

It builds the PE graph adapters with MSVC, independently rebuilds the same
authored graph twice, and checks original virtual paths, text encodings,
module identity, live bindings and worker resource loading. The generated
program is a fixture, not Claude Code. No source samples or executable files
are uploaded; the artifact contains diagnostic output and a JSON receipt.

The native runtime check is not an OS sandbox qualification or proof of
original/reconstructed client equivalence. Those acceptance steps remain
separate and must pass before the overall recovery goal can close.

The existing Intel HVF workflows are unrelated and retain their current state.
