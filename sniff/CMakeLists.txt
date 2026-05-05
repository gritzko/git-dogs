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

#  sniff-cli is a thin parser/exec wrapper around snifflib.  Under
#  the new arrangement (dog/DOG.md §10a) sniff drives no other dog —
#  graf/spot reindex themselves when `be` spawns them — so the cli
#  links snifflib only.  graflib stays in snifflib's deps because
#  PATCH still calls graf for 3-way merges.
add_executable(sniff-cli SNIFF.cli.c)
target_link_libraries(sniff-cli snifflib)
set_target_properties(sniff-cli PROPERTIES OUTPUT_NAME sniff RUNTIME_OUTPUT_DIRECTORY ${DOG_BIN_DIR})

add_subdirectory(test)
