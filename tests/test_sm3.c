#include "smcryptoc/sm3.h"

int main() {
    uint8_t msg[] = {97, 98, 99};
    char* result = sm3_hash(msg, 3);
    printf("%s\n", result);
    free(result);
    return 0;
}