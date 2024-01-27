#include "smcryptoc/sm4.h"

int main() {
    uint8_t data[] = {97, 98, 99};
    uint8_t key[] = {49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56};
    size_t enc_size, dec_size;
    uint8_t* enc = encrypt_ecb(data, sizeof(data), key, &enc_size);
    uint8_t* dec = decrypt_ecb(enc, enc_size, key, &dec_size);
    free(dec);
    free(enc);

    return 0;
}