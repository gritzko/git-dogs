cmake_minimum_required(VERSION 3.20)
project(libdog C)

set(CMAKE_C_STANDARD 23)

set(CMAKE_EXPORT_COMPILE_COMMANDS on)


include_directories(.. .)

set(TEST_CXX_FLAGS "-g")
set(TEST_LDD_FLAGS "-g")

list(APPEND TOK_HEADERS
    TOK.h
    CT.h
    GOT.h
    PYT.h
    JST.h
    RST.h
    JAT.h
    CPPT.h
    CST.h
    HTMT.h
    CSST.h
    JSONT.h
    SHT.h
    RBT.h
    HST.h
    MLT.h
    JLT.h
    PHPT.h
    AGDT.h
    VERT.h
    TST.h
    KTT.h
    SCLT.h
    SWFT.h
    DARTT.h
    ZIGT.h
    DT.h
    LUAT.h
    PRLT.h
    RT.h
    ELXT.h
    ERLT.h
    NIMT.h
    NIXT.h
    VIMT.h
    YMLT.h
    TOMLT.h
    SQLT.h
    GQLT.h
    PRTT.h
    HCLT.h
    SCSST.h
    LAXT.h
    CLJT.h
    CMKT.h
    DKFT.h
    FORT.h
    FSHT.h
    GLMT.h
    GLST.h
    MAKT.h
    ODNT.h
    PWST.h
    SOLT.h
    TYST.h
    TXTT.h
    MDT.h
    MKDT.h
    LLT.h
)

list(APPEND TOK_SOURCES
    TOK.c
    IGNO.c
    CT.c
    CT.rl.c
    GOT.c
    GOT.rl.c
    PYT.c
    PYT.rl.c
    JST.c
    JST.rl.c
    RST.c
    RST.rl.c
    JAT.c
    JAT.rl.c
    CPPT.c
    CPPT.rl.c
    CST.c
    CST.rl.c
    HTMT.c
    HTMT.rl.c
    CSST.c
    CSST.rl.c
    JSONT.c
    JSONT.rl.c
    SHT.c
    SHT.rl.c
    RBT.c
    RBT.rl.c
    HST.c
    HST.rl.c
    MLT.c
    MLT.rl.c
    JLT.c
    JLT.rl.c
    PHPT.c
    PHPT.rl.c
    AGDT.c
    AGDT.rl.c
    VERT.c
    VERT.rl.c
    TST.c
    TST.rl.c
    KTT.c
    KTT.rl.c
    SCLT.c
    SCLT.rl.c
    SWFT.c
    SWFT.rl.c
    DARTT.c
    DARTT.rl.c
    ZIGT.c
    ZIGT.rl.c
    DT.c
    DT.rl.c
    LUAT.c
    LUAT.rl.c
    PRLT.c
    PRLT.rl.c
    RT.c
    RT.rl.c
    ELXT.c
    ELXT.rl.c
    ERLT.c
    ERLT.rl.c
    NIMT.c
    NIMT.rl.c
    NIXT.c
    NIXT.rl.c
    VIMT.c
    VIMT.rl.c
    YMLT.c
    YMLT.rl.c
    TOMLT.c
    TOMLT.rl.c
    SQLT.c
    SQLT.rl.c
    GQLT.c
    GQLT.rl.c
    PRTT.c
    PRTT.rl.c
    HCLT.c
    HCLT.rl.c
    SCSST.c
    SCSST.rl.c
    LAXT.c
    LAXT.rl.c
    CLJT.c
    CLJT.rl.c
    CMKT.c
    CMKT.rl.c
    DKFT.c
    DKFT.rl.c
    FORT.c
    FORT.rl.c
    FSHT.c
    FSHT.rl.c
    GLMT.c
    GLMT.rl.c
    GLST.c
    GLST.rl.c
    MAKT.c
    MAKT.rl.c
    ODNT.c
    ODNT.rl.c
    PWST.c
    PWST.rl.c
    SOLT.c
    SOLT.rl.c
    TYST.c
    TYST.rl.c
    TXTT.rl.c
    MDT.c
    MDT.rl.c
    MKDT.c
    MKDT.rl.c
    LLT.c
    LLT.rl.c
)

list(APPEND TOK_HEADERS KEYW.h)
list(APPEND TOK_SOURCES KEYW.c)

list(APPEND TOK_HEADERS BRCT.h)
list(APPEND TOK_SOURCES BRCT.c)

list(APPEND TOK_HEADERS DEF.h)
list(APPEND TOK_SOURCES DEF.c)

list(APPEND TOK_HEADERS HUNK.h)
list(APPEND TOK_SOURCES HUNK.c)

list(APPEND TOK_HEADERS HOME.h)
list(APPEND TOK_SOURCES HOME.c)

list(APPEND TOK_HEADERS FRAG.h)
list(APPEND TOK_SOURCES FRAG.rl.c)

list(APPEND TOK_HEADERS QURY.h)
list(APPEND TOK_SOURCES QURY.rl.c)

list(APPEND TOK_HEADERS DPATH.h)
list(APPEND TOK_SOURCES DPATH.rl.c)

list(APPEND TOK_HEADERS ULOG.h)
list(APPEND TOK_SOURCES ULOG.c)

list(APPEND TOK_HEADERS DOG.h)
list(APPEND TOK_SOURCES DOG.c)

list(APPEND TOK_HEADERS CLI.h)
list(APPEND TOK_SOURCES CLI.c)

add_library(dog STATIC ${TOK_HEADERS} ${TOK_SOURCES}
            sha1dc/sha1.c sha1dc/ubc_check.c)
target_link_libraries(dog abc-core)

add_executable(dogtok TOK.cli.c)
target_link_libraries(dogtok dog abc-core)

add_subdirectory(test)

if (WITH_FUZZ)
add_subdirectory(fuzz)
endif()
