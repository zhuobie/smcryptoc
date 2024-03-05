#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include "gmp.h"
#include "libtasn1.h"

typedef struct VecU8 {
    uint8_t* data;
    size_t len;
} VecU8;

VecU8* init_vecu8();
void destroy_vecu8(VecU8* vecu8);
void push_vecu8(VecU8* vecu8, const uint8_t e);
void push_vec_vecu8(VecU8* vecu8, const uint8_t* vec, const size_t vec_size);
void push_vecu8_vecu8(VecU8* vecu8, const VecU8* vecu8_push);
void unshift_vecu8(VecU8* vecu8, const uint8_t e);
void unshift_vec_vecu8(VecU8* vecu8, uint8_t* vec, const size_t vec_size);
void unshift_vecu8_vecu8(VecU8* vecu8, const VecU8* vecu8_unshift);
void insert_vec_vecu8(VecU8* vecu8, const size_t position, uint8_t* vec, size_t vec_size);

void bytes_to_file(const uint8_t* file_bytes, const size_t file_size, const char* file_path);
uint8_t* bytes_from_file(const char* file_path);
char* random_hex(const size_t size);
char* format_hex(const char* hex_1, const char* hex_2);
uint8_t* concvec(const uint8_t* vec_1, const size_t vec_1_size, const uint8_t* vec_2, const size_t vec_2_size);
uint8_t* appendzero(const uint8_t* data, const size_t data_size, const size_t size);
uint8_t* removezero(const uint8_t* data, const size_t data_size, const size_t size);
uint8_t* append_remove_zero(const uint8_t* data, const size_t data_size, const size_t size);
void u32_to_byte_array(const uint32_t value, uint8_t byte_array[4]);
void byte_array_to_u32(const uint8_t byte_array[4], uint32_t* value);
void mpz_to_hex(const mpz_t mpz, char* hex);
void hex_to_mpz(const char* hex, mpz_t* mpz);
uint8_t* mpz_to_byte_array(const mpz_t mpz, size_t* array_size);
void byte_array_to_mpz(const uint8_t* byte_array, size_t byte_array_size, mpz_t* mpz);
uint8_t* pad_zero_positive(const uint8_t* mpz_byte_array, const size_t mpz_byte_array_size, int* pad);
uint32_t rotate_left(const uint32_t num, const uint32_t shift);
uint32_t rotate_right(const uint32_t num, const uint32_t shift);
void to_be_bytes(const uint32_t value, uint8_t byte_array[4]);
void from_be_bytes(const uint8_t* byte_array, uint32_t* value);
char* byte_array_to_hex(const uint8_t* byte_array, const size_t byte_array_size);
uint8_t hex_to_byte(const char hex_char);
uint8_t* hex_to_byte_array(const char* hex_string, const size_t hex_string_size);
uint8_t* xor_vector(const uint8_t* a, const uint8_t* b, const size_t size);

#endif