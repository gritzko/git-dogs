#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int mul(int a, int b) {
    return a * b;
}

int sub(int a, int b) {
    return a - b;
}

int neg(int a) {
    return -a;
}

void greet(const char *name) {
    printf(<<<<"trunk: %s\n"||||"fix! %s\n">>>>, name);
}

int main(void) {
    int x = add(10, 20);
    int y = sub(50, 30);
    greet("world");
<<<<    int diff = x - y;
    fputs("trunk done\n", stdout);
||||    while (y > 0) {
        y = y - x;
    }
    fprintf(stderr, "fix loop done\n");
>>>>    return diff;
}
