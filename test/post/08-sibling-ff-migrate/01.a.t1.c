#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int main(void) {
    printf("add=%d\n", add(2, 3));
    return 0;
}
