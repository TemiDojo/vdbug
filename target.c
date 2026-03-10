#include <stdio.h>

int f();

int main(void) {
    
    int x = 0;
    x= x + f();
    return x + 20;
}

int f() {

    return 20;
}
