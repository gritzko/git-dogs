cmake_minimum_required(VERSION 3.20)
project(sniff C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS on)


include_directories(.. .)

add_library(snifflib STATIC
    SNIFF.h SNIFF.c SNIFF.exe.c
    AT.h AT.c
    GET.h GET.c POST.h POST.c PUT.h PUT.c DEL.h DEL.c CLASS.h CLASS.c
    PATCH.h PATCH.c
    LS.h LS.c
    ../abc/FSW.c)
target_link_libraries(snifflib graflib keeplib gitcompat dog abc-core)

#  sniff-cli mirrors keeper-cli's indexer fan-out (see SNIFF.cli.c) so
#  every object KEEPPackFeed writes during a local commit also reaches
#  graf/spot via DOGUpdate.  graflib + spotlib are forward-resolved at
#  generate-time even though their subdirs are added earlier in the
#  top-level CMakeLists.
add_executable(sniff-cli SNIFF.cli.c)
target_link_libraries(sniff-cli graflib spotlib snifflib)
set_target_properties(sniff-cli PROPERTIES OUTPUT_NAME sniff RUNTIME_OUTPUT_DIRECTORY ${DOG_BIN_DIR})

add_subdirectory(test)
