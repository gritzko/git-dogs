#include <stdio.h>

int sub(int a, int b) {
    return a - b;
}

int main(void) {
    printf("sub=%d\n", sub(5, 2));
    return 0;
}
