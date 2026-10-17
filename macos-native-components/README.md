# Mach-O component verification

`macho_objects.py` compares little-endian x86_64 and ARM64 relocatable objects
before and after a specified symbol rename. It compares every section body
(including debug data), section attributes, typed symbols, ordered relocation
references, symbol-table partitions, indirect symbols, and supported link-edit
metadata. ARM64 addend relocations retain their numeric addend. Unsupported
load commands and malformed ranges fail explicitly.

This verifier accepts plain machine-code objects, not LLVM bitcode. It does not
by itself qualify a Ugrep build or a recovered client. The initial owned
controls use Apple Clang 17 and LLVM objcopy 18: three real C/assembly rewrites
pass, and 19 mutations of code, binding, descriptors, relocation targets,
addends, command types and file bounds are rejected. Full component builds
must retain both object graphs and rerun the comparison with their actual
toolchain.
