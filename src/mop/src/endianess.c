#include "endianess.h"

int little_endian() {
    unsigned int m = 0x00000001;
    return (*(&m) & 1);
}
