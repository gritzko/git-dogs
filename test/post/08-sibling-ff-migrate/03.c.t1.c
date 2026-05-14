#include <stdio.h>

int mul(int a, int b) {
    return a * b;
}

int main(void) {
    printf("mul=%d\n", mul(3, 4));
    return 0;
}
