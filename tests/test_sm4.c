#include "smcryptoc/sm4.h"

int main() {
    uint8_t data[] = {97, 98, 99};
    uint8_t key[] = {49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56};
    size_t enc_size, dec_size;
    uint8_t* enc = encrypt_ecb(data, sizeof(data), key, &enc_size);
    uint8_t* dec = decrypt_ecb(enc, enc_size, key, &dec_size);
    free(dec);
    free(enc);

    uint8_t data_cbc[] = {97, 98, 99};
    uint8_t key_cbc[] = {49, 50, 51, 52, 53, 54, 55, 56, 49, 50, 51, 52, 53, 54, 55, 56};
    uint8_t iv_cbc[] = {48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48, 48};
    size_t enc_size_cbc, dec_size_cbc;
    uint8_t* enc_cbc = encrypt_cbc(data_cbc, sizeof(data_cbc), key_cbc, iv_cbc, &enc_size_cbc);
    uint8_t* dec_cbc = decrypt_cbc(enc_cbc, enc_size_cbc, key_cbc, iv_cbc, &dec_size_cbc);
    free(dec_cbc);
    free(enc_cbc);
    
    return 0;
}