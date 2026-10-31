# Fixed throwing predicate with public Set.filter

This new authored client supplies a fixed named function through a closure,
instead of taking a predicate parameter. The predicate has a visible nonconstant
NSObject hash input, an actual throwing branch, and inline(never). The client
has only its Set input in Swift source. Compiler output remains the authority
for all lowered declarations, hidden roles, and specialized function bodies.

Five fixed Xcode 26.5 Swift 6.3.2 Darwin profiles produce IR, SIL and assembly.
Compiler and SDK settings hashes must match; old version text is reused. No
module compilation, original WMF input, generated code execution, or simulator
launch is part of this job. No symbol, complete-body match, ABI, value, provider,
frame, borrow, lifetime, effect, or source publication result is predicted.
The previous successful and failed source domains remain closed and intact.
