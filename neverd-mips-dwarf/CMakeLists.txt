cmake_minimum_required(VERSION 3.20)
project(MipsDwarfImport LANGUAGES C CXX)
find_package(LLVM REQUIRED CONFIG)
llvm_map_components_to_libnames(dwarf_libs DebugInfoDWARF Object Support)

# Use the consumer's complete type-library source and its generated headers.
function(add_neverd_component_library name)
  add_library(${name} STATIC ${ARGN})
  target_compile_features(${name} PUBLIC cxx_std_20)
  target_include_directories(${name} PUBLIC "${NEVERD}/include" ${LLVM_INCLUDE_DIRS})
endfunction()
set(PROJECT_SOURCE_DIR "${NEVERD}")
add_subdirectory("${NEVERD}/lib/types" types)

add_executable(mips-layout-reader reader.cpp)
target_link_libraries(mips-layout-reader PRIVATE NeverDTypes ${dwarf_libs})
