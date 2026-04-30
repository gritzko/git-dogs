cmake_minimum_required(VERSION 3.20)
project(beagle C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_EXPORT_COMPILE_COMMANDS on)


include_directories(.. .)

add_executable(be-cli BE.cli.c)
target_compile_definitions(be-cli PRIVATE NDEBUG)
target_link_libraries(be-cli snifflib graflib spotlib keeplib gitcompat dog abc-core)
set_target_properties(be-cli PROPERTIES OUTPUT_NAME be RUNTIME_OUTPUT_DIRECTORY ${DOG_BIN_DIR})

add_subdirectory(test)
