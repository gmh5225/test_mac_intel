# Typed predicate with public Set.filter error erasure

The predicate retains its generic Failure: Error typed throws clause. The
public client uses the SDK Set.filter outer any Error convention. These two
outer throws changes follow the preserved first compiler diagnostics; the
failed full typed-outer source and job remain intact.

Five fixed Xcode 26.5 Swift 6.3.2 Darwin profiles produce IR, SIL and assembly
with all actual commands, exits, Make rules and dependencies retained. Compiler
and SDK settings hashes must match. Version text is reused. Outputs are static
compiler evidence. Original WMF ABI, frame, value, provider, lifetime, effect
and source publication gates remain independent.
