#include <stdio.h>

int sub(int a, int b) {
    return a - b;
}

int main(void) {
    printf("sub=%d\n", sub(7, 3));
    return 0;
}
