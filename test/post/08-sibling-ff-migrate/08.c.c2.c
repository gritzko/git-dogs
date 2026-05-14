#include <stdio.h>

int mul(int a, int b) {
    int r = 0;
    for (int i = 0; i < b; ++i) {
        r += a;
    }
    return r;
}

int main(void) {
    printf("mul=%d\n", mul(3, 4));
    return 0;
}
