add_executable(DAG01test DAG01.c)
target_link_options(DAG01test PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(DAG01test PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(DAG01test graflib dog abc-core)
add_test(NAME DAG01test COMMAND DAG01test)

add_executable(JOIN01test JOIN01.c)
target_link_options(JOIN01test PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(JOIN01test PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(JOIN01test graflib dog abc-core)
add_test(NAME JOIN01test COMMAND JOIN01test)

add_executable(WEAVE01test WEAVE01.c)
target_link_options(WEAVE01test PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(WEAVE01test PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(WEAVE01test graflib dog abc-core)
add_test(NAME WEAVE01test COMMAND WEAVE01test)

add_executable(NEIL01test NEIL01.c)
target_link_options(NEIL01test PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(NEIL01test PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(NEIL01test graflib dog abc-core)
add_test(NAME NEIL01test COMMAND NEIL01test)

add_executable(REBASE01test REBASE01.c)
target_link_options(REBASE01test PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(REBASE01test PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(REBASE01test graflib dog keeplib abc-core)
add_test(NAME REBASE01test COMMAND REBASE01test)
set_tests_properties(REBASE01test PROPERTIES
    ENVIRONMENT "TMP=${DOG_TEST_TMP_ROOT};TEST_ID=REBASE01test")

add_executable(MERGEWT01test MERGEWT01.c)
target_link_options(MERGEWT01test PRIVATE ${TEST_LDD_FLAGS})
target_compile_options(MERGEWT01test PRIVATE ${TEST_CXX_FLAGS})
target_link_libraries(MERGEWT01test graflib dog keeplib abc-core)
add_test(NAME MERGEWT01test COMMAND MERGEWT01test)
set_tests_properties(MERGEWT01test PROPERTIES
    ENVIRONMENT "TMP=${DOG_TEST_TMP_ROOT};TEST_ID=MERGEWT01test")

add_test(NAME GRAFcli_diff_artifact
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/diff_test.sh
        $<TARGET_FILE:graf-cli>
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR})
set_tests_properties(GRAFcli_diff_artifact PROPERTIES
    ENVIRONMENT "TMP=${DOG_TEST_TMP_ROOT};TEST_ID=GRAFcli_diff_artifact")

#  toy.sh — full-pipeline smoke test: be post x3, graf diff, merge,
#  blame, weave, index/status.  Exercises dog/DOG.md §8 entry points.
add_test(NAME GRAFtoy
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/toy.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(GRAFtoy PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=GRAFtoy")

#  get.sh — URI-driven deterministic blob merge (`graf get <uri>`).
add_test(NAME GRAFget
    COMMAND bash ${CMAKE_CURRENT_SOURCE_DIR}/get.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(GRAFget PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=GRAFget")

if (WITH_SSH)
    #  merge-from-git.sh — toy git source with two branches, keeper fetch
    #  drives graf indexing, `graf get path?sha_a&sha_b` merges concurrent
    #  disjoint edits.  Requires ssh-to-localhost (same as the beagle
    #  git-backed tests).
    add_test(NAME GRAFmergeFromGit
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/merge-from-git.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(GRAFmergeFromGit PROPERTIES
        ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=GRAFmergeFromGit")

    #  mill-merges.sh — 3-way merge treadmill against curated merges in
    #  ~/src/git.  Each case fetches the two parents via keeper (ssh
    #  localhost, same transport as mill-tags.sh) and compares
    #  `graf get <path>?<P1>&<P2>` against `git show <merge>:<path>`.
    #  Heavy (pulls real history) — ctest runs it only when explicitly
    #  selected.  Toggle via `-DGRAF_MILL_MERGES=ON` or set it in the
    #  environment.
    option(GRAF_MILL_MERGES "Register the graf merge-treadmill test" OFF)
    if (GRAF_MILL_MERGES)
        add_test(NAME GRAFmillMerges
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/mill-merges.sh
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
        set_tests_properties(GRAFmillMerges PROPERTIES
            ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=GRAFmillMerges")
    endif()
endif()
