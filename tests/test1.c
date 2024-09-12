#include <stdio.h>

// Add some DWARF debug info by using inline functions
static inline int add(int a, int b) {
    return a + b;
}

static inline int multiply(int a, int b) {
    return a * b;
}

// Add some relocations and dynamic symbols
__attribute__((visibility("default")))
int calculate(int a, int b) {
    return add(a, b) * multiply(a, b);
}

int main() {
    printf("Result: %d\n", calculate(3, 4));
    return 0;
}