//  Stub: real CLI test not yet authored.  Compiles + passes so the
//  CMake target stays satisfiable; replace when the actual test
//  table lands.
#include "abc/PRO.h"
#include "abc/TEST.h"

ok64 CLItest(void) {
    sane(1);
    done;
}

TEST(CLItest);
