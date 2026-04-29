cmake_minimum_required(VERSION 3.20)
project(keeper C)
set(CMAKE_C_STANDARD 23)
include_directories(.. .)

find_package(ZLIB REQUIRED)

add_library(gitcompat STATIC GIT.c PKT.c PACK.c DELT.c ZINF.c SHA1.c)
target_link_libraries(gitcompat dog abc-core ZLIB::ZLIB)

add_library(keeplib STATIC KEEP.c KEEP.exe.c REFS.c REFADV.c WALK.c UNPK.c PSTR.c WIRE.c WIRECLI.c RECV.c PROJ.c)
target_link_libraries(keeplib gitcompat dog abc-core)

#  keeper-cli links graflib/spotlib so its indexer fan-out (installed
#  in KEEP.cli.c) can call GRAFUpdate/SPOTUpdate on every resolved
#  object.  keeplib itself stays free of those deps (no cycles).
#  Targets are resolved at generate-time, so forward references to
#  graflib (added later in the top-level CMakeLists) are fine.
add_executable(keeper-cli KEEP.cli.c)
target_link_libraries(keeper-cli graflib spotlib keeplib gitcompat dog abc-core)
set_target_properties(keeper-cli PROPERTIES OUTPUT_NAME keeper RUNTIME_OUTPUT_DIRECTORY ${DOG_BIN_DIR})

add_executable(git-dl git-dl.cli.c)
target_link_libraries(git-dl keeplib gitcompat dog abc-core)

add_subdirectory(test)
