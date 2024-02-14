#ifndef SM2_H
#define SM2_H

#include "smcryptoc/utils.h"

char* gen_sk();
char* pk_from_sk(const char* private_key);
uint8_t* sign_raw(const uint8_t* data, size_t data_len, const char* private_key, size_t* size);
int verify_raw(const uint8_t* data, const size_t data_len, const uint8_t* sign_bytes, const char* public_key);
uint8_t* encrypt_raw(const uint8_t* data, const size_t data_size, const char* public_key, size_t* size);
uint8_t* decrypt_raw(const uint8_t* cipher, const size_t cipher_size, const char* private_key, size_t* size);
uint8_t* encrypt_byte(const uint8_t* data, const size_t data_size, const char* public_key, size_t* size);
uint8_t* decrypt_byte(const uint8_t* asn1_encrypt_data, const size_t enc_size, const char* private_key, size_t* size);

#endif