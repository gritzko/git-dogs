#include <stdio.h>

int dbl(int a) {
    return a + a;
}

int main(void) {
    printf("dbl=%d\n", dbl(21));
    return 0;
}
