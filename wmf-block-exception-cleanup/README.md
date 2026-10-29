# Independently authored Block exception cleanup

This new C++ fixture uses typed compiler-generated Blocks and stock SDK APIs.
It never uploads or executes WMF, generated WMF C or NeverD code. The source
runtime, precise SDK26.5 and four previous provider file identities are checked
again on this runner. The current C++ ABI file receives a new static UUID,
whole-file and arm64-slice identity before compilation; both its throw and
personality symbol owners must match that UUID before the native cases begin.

Six new cases target both stack-capture constructors, both heap-capture copy
constructors, invocation after source-stack protection, and a two-capture normal
control. Every constructed instance has a unique logical id; failed constructors
never become live. All events are flushed before any later possible failure.
For constructor exceptions, cleanup occurs before the source pthread joins.
For successful copies, invocation and final heap-capture disposal occur while
the old source stack remains PROT_NONE. Only the fixture's own stack is protected.

Finite authored exceptions do not certify the original provider match, callback
ABI, capture validity, frame access, ownership, lifetime, effects or source unit.
The observers inspect dlsym addresses without casting them to callable types.
The loaded and on-disk headers remain separate observations. No old successful
fixture, compiler, raw metadata query, SDK build or FULL evaluation is restarted.
