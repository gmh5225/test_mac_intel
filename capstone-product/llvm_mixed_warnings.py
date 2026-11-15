from pathlib import Path
import hashlib, json, sys
root=Path(sys.argv[1]); receipt=Path(sys.argv[2])
file=root/'llvm/cmake/modules/HandleLLVMOptions.cmake'
text=file.read_text(); before=hashlib.sha256(file.read_bytes()).hexdigest()
flags=['-Werror=unguarded-availability-new','-Wcovered-switch-default','-Wstring-conversion']
for flag in flags:
 old='append("'+flag+'" CMAKE_C_FLAGS CMAKE_CXX_FLAGS)'
 assert text.count(old)==1,(flag,text.count(old))
 replacement='append("'+flag+'" CMAKE_CXX_FLAGS)\n  if (CMAKE_C_COMPILER_ID MATCHES "Clang")\n    append("'+flag+'" CMAKE_C_FLAGS)\n  endif()'
 text=text.replace(old,replacement)
file.write_text(text)
receipt.write_text(json.dumps(dict(file=str(file),before_sha256=before,after_sha256=hashlib.sha256(file.read_bytes()).hexdigest(),flags=flags,scope='Only select Clang-specific diagnostic flags separately for C and C++; no compiler optimization or source semantics changed'),indent=2)+'\n')
