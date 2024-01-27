#include "smcryptoc/sm2.h"

int main() {
    // generate private key and public key
    char* sk = gen_sk();
    char* pk = pk_from_sk(sk);

    // sign and verify
    uint8_t data[] = {97, 98, 99};
    size_t size;
    uint8_t* sign = sign_raw(data, sizeof(data), sk, &size);
    int verify = verify_raw(data, sizeof(data), sign, pk);
    // bytes_to_file(sign, size, "C:/Users/swufe/Desktop/sign_c.der");

    // encrypt_raw and decrypt_raw
    size_t enc_size, dec_size;
    uint8_t* enc = encrypt_raw(data, sizeof(data), pk, &enc_size);
    uint8_t* dec = decrypt_raw(enc, enc_size, sk, &dec_size);

    // assert
    printf("%d\n", verify);
    for (int i = 0; i < dec_size; i++) {
        printf("%d\n", dec[i]);
    }

    // free memory
    free(sign);
    free(enc);
    free(dec);
    free(pk);
    free(sk);
    return 0;
}
