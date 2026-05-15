# test/ — data-driven `be` integration cases.
#
# Each <verb>/<case>/ subdir gets its own ctest target named
# be-<verb>-<case>.  Discovery is via file(GLOB ...) so adding a new
# case dir does not require a CMake edit (re-run cmake to refresh).

# IMPORTANT: TMP must live OUTSIDE the dogs source tree.  `be` walks
# upward from the cwd looking for an existing `.be/` and would
# otherwise glue the test scratch onto the project's own repo
# (`/.../dogs/.be/`).  Use the timestamped run dir already created
# by the top-level CMakeLists.txt for the existing toy-repo tests.
set(_BE_TEST_TMP "${DOG_TEST_TMP_ROOT}/be-test")
file(MAKE_DIRECTORY "${_BE_TEST_TMP}")

# Glob <verb>/<case>/run.sh under this dir.  CONFIGURE_DEPENDS asks
# CMake to re-glob on rebuild, so newly added case dirs get picked up
# without a manual `cmake ..`.
file(GLOB _be_case_runs CONFIGURE_DEPENDS
    RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/*/*/run.sh")

# Tests in this list are drafted alongside spec rewrites, expected
# to FAIL until the implementation catches up.  Flip-back is part
# of the relevant impl PR.  See VERBS.todo.md for tracking.
set(_BE_WILL_FAIL_CASES
)

# Tests that need passwordless ssh to localhost (mirror what
# beagle/test/CMakeLists.txt does for roundtrip.sh).  Skipped when
# WITH_SSH is OFF so non-ssh dev environments stay green.  TMP must
# live under $HOME because keeper resolves `//host/path` URIs as
# remote-HOME-relative — case.sh's $SCRATCH already does (it sits
# under $HOME/tmp/run-<ts>/be-test/$$/<verb>/<name>).
set(_BE_NEEDS_SSH_CASES
    "be-post-05-non-ff-refused"
    "be-post-06-fetch-incremental"
    "be-get-05-submodule-from-ssh"
    "be-get-07-submodule-nosub"
)

foreach(_run ${_be_case_runs})
    # _run = "<verb>/<case>/run.sh"  →  verb / case
    get_filename_component(_case_dir "${_run}"     DIRECTORY)
    get_filename_component(_case_name "${_case_dir}" NAME)
    get_filename_component(_verb_dir  "${_case_dir}" DIRECTORY)
    get_filename_component(_verb_name "${_verb_dir}" NAME)

    # skip lib/ if it ever sprouts a run.sh by accident
    if (_verb_name STREQUAL "lib")
        continue()
    endif()

    set(_test_name "be-${_verb_name}-${_case_name}")
    if (_test_name IN_LIST _BE_NEEDS_SSH_CASES AND NOT WITH_SSH)
        continue()
    endif()

    add_test(NAME ${_test_name}
        COMMAND sh "${CMAKE_CURRENT_SOURCE_DIR}/${_run}"
        WORKING_DIRECTORY "${CMAKE_BINARY_DIR}")
    set_tests_properties(${_test_name} PROPERTIES
        ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${_BE_TEST_TMP}")
    if (_test_name IN_LIST _BE_WILL_FAIL_CASES)
        set_tests_properties(${_test_name} PROPERTIES WILL_FAIL TRUE)
    endif()
endforeach()
