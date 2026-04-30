# beagle tests

if (WITH_MILL)
    add_test(NAME mill
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/mill.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(mill PROPERTIES
        ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=mill")
endif()

# workflow.sh exercises be's get/put/post/delete dispatch against a
# toy worktree — mirrors sniff/test/workflow.sh but through `be`.
add_test(NAME BEworkflow
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/workflow.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(BEworkflow PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=BEworkflow")

# workflow-branches.sh has been split into 9 parallel-friendly cases
# under test/branches/01..09 (run via test/run.sh + xargs -P).  The
# monolith is retired; each cluster is a self-contained run.sh that
# the verbcheck-style harness picks up through CMakeLists test/branches.

# worktree.sh — `be get <localdir>` clones a local primary.
# Worktree layout: `.dogs` symlink to primary + local `.sniff` file.
add_test(NAME BEworktree
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/worktree.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(BEworktree PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=BEworktree")

# be-clone-sniff.sh — after a clone, `.sniff` must carry both rows
# (repo + get).  Pins the on-disk shape against silent regressions
# where only the bootstrap repo row survives.
add_test(NAME be-clone-sniff
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/be-clone-sniff.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(be-clone-sniff PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=be-clone-sniff")

# history.sh — put/post, delete/post, edit/post, then checkout an
# older commit by SHA (version handle = at.log tail).  No ssh.
add_test(NAME BEhistory
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/history.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(BEhistory PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=BEhistory")

# be-diff-projector.sh — VERBS.md `diff:` projector (file/tree, ref-vs-wt
# and ref-to-ref) routed through `be get diff:...` and verb-less
# `be diff:...` to graf's diff machinery.
add_test(NAME be-diff-projector
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/be-diff-projector.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(be-diff-projector PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=be-diff-projector")

# be-log-projector.sh — VERBS.md `log:` projector (branch parent-chain
# walk and per-file PATH_VER walk), one commit per line.
add_test(NAME be-log-projector
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/be-log-projector.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(be-log-projector PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=be-log-projector")

# be-map-projector.sh — VERBS.md `map:` projector (branch tree filter:
# trunk + current branch + ancestors-up-to-trunk + descendants;
# siblings excluded).
add_test(NAME be-map-projector
    COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/be-map-projector.sh
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
set_tests_properties(be-map-projector PROPERTIES
    ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=be-map-projector")

# --- verbcheck-driven verb matrix --------------------------------------
# Snapshot-and-diff per-verb tests built on verbcheck.sh.  Each
# be-<verb>-<case>.sh exercises one cell of the verb × scenario
# matrix; predicates are uniform (vc_assert_* helpers in verbcheck.sh).
foreach(vc
        be-get-dirty-cross
        be-get-dirty-overlap
        be-get-clean-switch
        be-get-create-on-miss
        be-get-absolute-miss
        be-get-restore-wiped
        be-get-overlay-clean
        be-get-overlay-real
        be-get-overlay-delete-dirty
        be-get-overlay-delete-clean
        be-get-overlay-no-baseline
        be-post-ff
        be-post-empty
        be-post-nonff
        be-post-rebase
        be-post-cross-create
        be-post-path-reject
        be-put-path
        be-delete-path
        be-delete-branch
        be-delete-branch-wt-on-it
        be-delete-branch-descendants
        be-delete-branch-resurrect
        be-patch-clean)
    add_test(NAME ${vc}
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/${vc}.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(${vc} PROPERTIES
        ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=${vc}")
endforeach()

if (WITH_SSH)
    # roundtrip.sh — full git <-> be flow: seed origin, clone over ssh,
    # make a worktree, edit, commit, push, diff.
    add_test(NAME BEroundtrip
        COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/roundtrip.sh
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
    set_tests_properties(BEroundtrip PROPERTIES
        ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=BEroundtrip")

    # Toy-repo matrix (3 commits, v1+v2 tags, master tip).  Each script
    # builds the same toy and rsync-compares git-side and keeper-side
    # worktrees after the same operation.  -from-git uses a vanilla git
    # server; -from-keeper seeds a keeper mirror first and serves it
    # via `keeper upload-pack`.  Requires passwordless ssh to localhost.
    foreach(toy blobs-from-git tag-blobs-from-keeper clone-from-git clone-from-keeper tags-from-git tags-from-keeper)
        add_test(NAME ${toy}
            COMMAND sh ${CMAKE_CURRENT_SOURCE_DIR}/${toy}.sh
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
        set_tests_properties(${toy} PROPERTIES
            ENVIRONMENT "BIN=${DOG_BIN_DIR};TMP=${DOG_TEST_TMP_ROOT};TEST_ID=${toy}")
    endforeach()
endif()

# clone-git.sh and mill-tags.sh are manual heavyweight integration
# scripts (require $HOME/src/git + ssh localhost); run directly.
