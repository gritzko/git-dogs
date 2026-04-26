cmake_minimum_required(VERSION 3.20)
project(dog C)

set(CMAKE_C_STANDARD 23)

set(CMAKE_EXPORT_COMPILE_COMMANDS on)


include_directories(.. ../..)

set(TEST_CXX_FLAGS "-g")
set(TEST_LDD_FLAGS "-g")

add_executable(TOK01test TOK01.c)
target_link_options(TOK01test PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(TOK01test PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(TOK01test dog abc-core)
add_test(NAME TOK01test COMMAND TOK01test)

add_executable(KEYWtest KEYW.c)
target_link_options(KEYWtest PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(KEYWtest PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(KEYWtest dog abc-core)
add_test(NAME KEYWtest COMMAND KEYWtest)

add_executable(BRCTtest BRCT.c)
target_link_options(BRCTtest PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(BRCTtest PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(BRCTtest dog abc-core)
add_test(NAME BRCTtest COMMAND BRCTtest)

add_executable(DEFtest DEF.c)
target_link_options(DEFtest PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(DEFtest PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(DEFtest dog abc-core)
add_test(NAME DEFtest COMMAND DEFtest)

add_executable(DEF01test DEF01.c)
target_link_options(DEF01test PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(DEF01test PRIVATE ${TEST_CXX_FLAGS})
target_compile_definitions(DEF01test PRIVATE TEST_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_link_libraries(DEF01test dog abc-core)
add_test(NAME DEF01test COMMAND DEF01test)

add_executable(IGNOtest IGNO.c)
target_link_options(IGNOtest PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(IGNOtest PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(IGNOtest dog abc-core)
add_test(NAME IGNOtest COMMAND IGNOtest)

add_executable(FRAGtest FRAG.c)
target_link_options(FRAGtest PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(FRAGtest PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(FRAGtest dog abc-core)
add_test(NAME FRAGtest COMMAND FRAGtest)

add_executable(QURYtest QURY.c)
target_link_options(QURYtest PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(QURYtest PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(QURYtest dog abc-core)
add_test(NAME QURYtest COMMAND QURYtest)

add_executable(DPATHtest DPATH.c)
target_link_options(DPATHtest PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(DPATHtest PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(DPATHtest dog abc-core)
add_test(NAME DPATHtest COMMAND DPATHtest)

add_executable(DOGtest DOG.c)
target_link_options(DOGtest PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(DOGtest PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(DOGtest dog abc-core)
add_test(NAME DOGtest COMMAND DOGtest)

add_executable(CLItest CLI.c)
target_link_options(CLItest PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(CLItest PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(CLItest dog abc-core)
add_test(NAME CLItest COMMAND CLItest)

add_executable(HOMEtest HOME.c)
target_link_options(HOMEtest PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(HOMEtest PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(HOMEtest dog abc-core)
add_test(NAME HOMEtest COMMAND HOMEtest)

add_executable(ULOGtest ULOG.c)
target_link_options(ULOGtest PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(ULOGtest PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(ULOGtest dog abc-core)
add_test(NAME ULOGtest COMMAND ULOGtest)

