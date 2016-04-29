#include "memory.h"
#include <stdio.h>

void *getseg(size_t s) {
    void *p = malloc(s);
    if (p == NULL) {
        printf("PANIC: no memory!\n");
        exit(1);
    }
    return p;
}
