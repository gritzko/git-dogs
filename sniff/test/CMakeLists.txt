add_executable(SNIFFtest SNIFF.c)
target_link_libraries(SNIFFtest snifflib)
add_test(NAME SNIFFtest COMMAND SNIFFtest)

add_test(NAME SNIFFworkflow
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/workflow.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(SNIFFworkflow PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=SNIFFworkflow")

#  squash.sh — concurrent trunk + sub-branch edits folded back via
#  `sniff patch` + `sniff post` (one linear commit on the parent).
add_test(NAME SNIFFsquash
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/squash.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(SNIFFsquash PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=SNIFFsquash")

#  ls.sh — `sniff ls` / `be get ls:` smoke test (three plain-text
#  modes + TLV framing sanity + non-destructive be routing).
add_test(NAME SNIFFls
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/ls.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(SNIFFls PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=SNIFFls")

#  dirty.sh — GET pre-flight: cross-branch dirty refuse + same-branch
#  overlap refuse + untracked-only carry-over + rollback semantics.
add_test(NAME SNIFFdirty
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/dirty.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(SNIFFdirty PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=SNIFFdirty")

#  post-ff.sh — POST pre-flight: empty-commit refuse + non-ff refuse
#  (REFS tip vs .sniff base divergence).
add_test(NAME SNIFFpostff
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/post-ff.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(SNIFFpostff PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=SNIFFpostff")

#  relref.sh — `?./X`, `?../X`, `?..` resolve via .sniff baseline.
add_test(NAME SNIFFrelref
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/relref.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(SNIFFrelref PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=SNIFFrelref")

#  branchdel.sh — `sniff delete ?branch` writes a tombstone +
#  safety checks (current-wt, descendants, resurrection).
add_test(NAME SNIFFbranchdel
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/branchdel.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(SNIFFbranchdel PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=SNIFFbranchdel")

#  cross-post.sh — `sniff post -m "msg" ?<target>` lands the new
#  commit on target only (other branches in REFS unchanged) +
#  non-ff cross-branch refusal.
add_test(NAME SNIFFcrosspost
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/cross-post.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(SNIFFcrosspost PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=SNIFFcrosspost")

if (WITH_SSH)
    #  patch.sh — 3-way merge toys (sniff patch <ref>).  Needs ssh
    #  localhost (same transport as beagle/test/blobs-from-git.sh).
    add_test(NAME SNIFFpatch
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/patch.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(SNIFFpatch PROPERTIES
        ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=SNIFFpatch")

    #  post-roundtrip.sh — be get / be post / be post //origin
    #  end-to-end: clone, edit, commit, push back, verify the bare
    #  remote's git log + tree + parent linkage + pack-size budget.
    add_test(NAME SNIFFpostroundtrip
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/post-roundtrip.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(SNIFFpostroundtrip PROPERTIES
        ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=SNIFFpostroundtrip")
endif()

#  refuse.sh — coverage for the new refusal codes (PUTNONE on
#  baseline-clean / empty bare-put; DELDIRTY on user-edited).
add_test(NAME SNIFFrefuse
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/refuse.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(SNIFFrefuse PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=SNIFFrefuse")
