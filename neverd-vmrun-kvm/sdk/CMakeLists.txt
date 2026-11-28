cmake_minimum_required(VERSION 3.20)
project(vmrun_sdk_driver LANGUAGES C CXX)
find_package(LLVM REQUIRED CONFIG)
add_executable(emit-vmrun emit-vmrun.c)
target_include_directories(emit-vmrun PRIVATE ${LLVM_INCLUDE_DIRS})
llvm_map_components_to_libnames(llvm_libs
  core irreader x86codegen x86asmparser x86desc x86info target mc
  codegen asmparser analysis support)
target_link_libraries(emit-vmrun PRIVATE ${llvm_libs})
