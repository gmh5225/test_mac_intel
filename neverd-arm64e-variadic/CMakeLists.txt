cmake_minimum_required(VERSION 3.22)
project(NeverDNativeReplay NONE)
enable_testing()
include(GoogleTest)

add_executable(NeverDArm64eAnalysisTests IMPORTED)
set_property(TARGET NeverDArm64eAnalysisTests PROPERTY IMPORTED_LOCATION
             "${NEVERD_REPLAY_HOST}")
gtest_discover_tests(NeverDArm64eAnalysisTests DISCOVERY_MODE PRE_TEST
                     NO_PRETTY_VALUES)
