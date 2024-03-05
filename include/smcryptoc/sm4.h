#ifndef SM4_H
#define SM4_H

#include "smcryptoc/utils.h"

uint8_t* encrypt_ecb(const uint8_t* p_input_data, const size_t p_input_data_size, 
                     const uint8_t key[16], size_t* output_data_size);
uint8_t* decrypt_ecb(const uint8_t* p_input_data, const size_t p_input_data_size, 
                     uint8_t key[16], size_t* output_data_size);
uint8_t* encrypt_cbc(const uint8_t* p_input_data, const size_t p_input_data_size,
                     const uint8_t key[16], const uint8_t p_iv[16], size_t* output_data_size);
uint8_t* decrypt_cbc(const uint8_t* p_input_data, const size_t p_input_data_size,
                     const uint8_t key[16], const uint8_t p_iv[16], size_t* output_data_size);

#endif