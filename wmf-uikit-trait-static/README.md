# Public UIKit DynamicSelf static profiles

Compile authored public UIKit queries and a UIViewController subclass using a
DynamicSelf trait callback. The generic trait accessor keeps the metadata and
UITraitEnvironment witness transport observable in compiler IR and SIL.

The single job retains every raw compiler output, SDK export text and command
result. It only prints compiler versions, reads SDK paths and export text, and
emits IR/SIL for five explicit targets. It does not boot Simulator, invoke any
callback, load WMF, execute original providers, or execute generated code.

Nine fake boundary tests cover the exact compiler allowlist and failure
retention. Successful compilation is collection evidence only; current ABI,
capture extent, lifetime, effects and original-body proofs remain separate.

The follow-up captures weak self as well as DynamicSelf metadata. The prior successful metadata-only capture sample is retained independently; neither sample is treated as original capture-layout or lifetime permission.

This follow-up uses the same authored weak/DynamicSelf source with -Onone to retain the separate closure implementation and forwarding declarations. Exactly 14 static commands and the same five SDK targets remain allowed. The optimized collection remains independently retained. No callback, executable, Simulator, original image or provider is run; original machine/body/identity/lifetime proofs remain mandatory.
