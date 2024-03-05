#include "smcryptoc/utils.h"

VecU8* init_vecu8() {
    VecU8* vecu8 = (VecU8*)malloc(sizeof(VecU8));
    vecu8->data = (uint8_t*)malloc(sizeof(uint8_t) * 0);
    vecu8->len = 0;
    return vecu8;
}

void destroy_vecu8(VecU8* vecu8) {
    free(vecu8->data);
    free(vecu8);
}

void push_vecu8(VecU8* vecu8, const uint8_t e) {
    vecu8->data = (uint8_t*)realloc(vecu8->data, sizeof(uint8_t) * (vecu8->len + 1));
    (vecu8->data)[vecu8->len] = e;
    vecu8->len += 1;
}

void push_vec_vecu8(VecU8* vecu8, const uint8_t* vec, const size_t vec_size) {
    vecu8->data = (uint8_t*)realloc(vecu8->data, sizeof(uint8_t) * (vecu8->len + vec_size));
    memcpy(vecu8->data + vecu8->len, vec, sizeof(uint8_t) * vec_size);
    vecu8->len += vec_size;
}

void push_vecu8_vecu8(VecU8* vecu8, const VecU8* vecu8_push) {
    vecu8->data = (uint8_t*)realloc(vecu8->data, sizeof(uint8_t) * (vecu8->len + vecu8_push->len));
    memcpy(vecu8->data + vecu8->len, vecu8_push->data, sizeof(uint8_t) * vecu8_push->len);
    vecu8->len += vecu8_push->len;
}

void unshift_vecu8(VecU8* vecu8, const uint8_t e) {
    VecU8* vecu8_copy = init_vecu8();
    memcpy(vecu8_copy->data, vecu8->data, sizeof(uint8_t) * vecu8->len);
    vecu8_copy->len = vecu8->len;
    vecu8->data = (uint8_t*)realloc(vecu8->data, sizeof(uint8_t) * (vecu8->len + 1));
    memcpy(vecu8->data + 1, vecu8_copy->data, sizeof(uint8_t) * vecu8_copy->len);
    (vecu8->data)[0] = e;
    vecu8->len += 1;
    destroy_vecu8(vecu8_copy);
}

void insert_vec_vecu8(VecU8* vecu8, const size_t position, uint8_t* vec, size_t vec_size) {
    uint8_t* vecu8_l = (uint8_t*)malloc(sizeof(uint8_t) * position);
    uint8_t* vecu8_r = (uint8_t*)malloc(sizeof(uint8_t) * (vecu8->len - position));
    size_t vecu8_l_size = position;
    size_t vecu8_r_size = (vecu8->len - position);
    memcpy(vecu8_l, vecu8->data, vecu8_l_size);
    memcpy(vecu8_r, vecu8->data + position, vecu8_r_size);
    vecu8->data = (uint8_t*)realloc(vecu8->data, sizeof(uint8_t) * (vecu8->len + vec_size));
    vecu8->len += vec_size;
    memcpy(vecu8->data, vecu8_l, sizeof(uint8_t) * vecu8_l_size);
    memcpy(vecu8->data + vecu8_l_size, vec, sizeof(uint8_t) * vec_size);
    memcpy(vecu8->data + vecu8_l_size + vec_size, vecu8_r, sizeof(uint8_t) * vecu8_r_size);
    free(vecu8_l);
    free(vecu8_r);
}

void unshift_vec_vecu8(VecU8* vecu8, uint8_t* vec, size_t vec_size) {
    uint8_t* new_data = (uint8_t*)malloc(sizeof(uint8_t) * (vecu8->len + vec_size));
    memcpy(new_data, vec, sizeof(uint8_t) * vec_size);
    memcpy(new_data + vec_size, vecu8->data, sizeof(uint8_t) * vecu8->len);
    free(vecu8->data);
    vecu8->data = new_data;
    vecu8->len += vec_size;
}

void unshift_vecu8_vecu8(VecU8* vecu8, const VecU8* vecu8_unshift) {
    VecU8* vecu8_copy = init_vecu8();
    memcpy(vecu8_copy->data, vecu8->data, sizeof(uint8_t) * vecu8->len);
    vecu8_copy->len = vecu8->len;
    vecu8->data = (uint8_t*)realloc(vecu8->data, sizeof(uint8_t) * (vecu8->len + vecu8_unshift->len));
    memcpy(vecu8->data + vecu8_unshift->len, vecu8_copy->data, sizeof(uint8_t) * vecu8_copy->len);
    memcpy(vecu8->data, vecu8_unshift->data, sizeof(uint8_t) * vecu8_unshift->len);
    vecu8->len += vecu8_unshift->len;
    destroy_vecu8(vecu8_copy);
}

void bytes_to_file(const uint8_t* file_bytes, const size_t file_size, const char* file_path) {
    FILE* file = fopen(file_path, "wb");
    if (file == NULL) {
        perror("unable to open file");
        exit(1);
    }
    size_t bytes_write = fwrite(file_bytes, sizeof(uint8_t), file_size, file);
    if (bytes_write != file_size) {
        perror("unable to write file");
        exit(1);
    }
    fclose(file);
}

uint8_t* bytes_from_file(const char* file_path) {
    FILE* file = fopen(file_path, "rb");
    if (file == NULL) {
        perror("unable to open file");
        exit(1);
    }
    fseek(file, 0, SEEK_END);
    size_t file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    uint8_t* file_bytes = (uint8_t*)malloc(file_size);
    if (file_bytes == NULL) {
        perror("unable to allocate memory");
        fclose(file);
        exit(1);
    }
    fread(file_bytes, sizeof(uint8_t), file_size, file);
    fclose(file);
    return file_bytes;
}

char* random_hex(const size_t size) {
    char c[] = "0123456789abcdef";
    char* hex = (char*)malloc(sizeof(char) * (size + 1));
    if (hex == NULL) {
        perror("unable to allocate memory");
        exit(1);
    }
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    srand(ts.tv_sec * 1000000000 + ts.tv_nsec);
    for (int i = 0; i < size; i++) {
        int random_index = rand() % 16;
        hex[i] = c[random_index];
    }
    hex[size] = '\0';
    return hex;
}

char* format_hex(const char* hex_1, const char* hex_2) {
    char* hex = (char*)malloc(sizeof(char) * 129);
    char zero[] = {'0', '\0'};
    hex[0] = '\0';
    if (strlen(hex_1) < 64) {
        for (int i = 0; i < (64 - strlen(hex_1)); i++) {
            strncat(hex, zero, 1);
        }
        strncat(hex, hex_1, strlen(hex_1));
    } else {
        strncat(hex, hex_1, strlen(hex_1));
    }
    if (strlen(hex_2) < 64) {
        for (int i = 64; i < (64 + 64 - strlen(hex_2)); i++) {
            strncat(hex, zero, 1);
        }
        strncat(hex, hex_2, strlen(hex_2));
    } else {
        strncat(hex, hex_2, strlen(hex_2));
    }
    return hex;
}

uint8_t* concvec(const uint8_t* vec_1, const size_t vec_1_size, const uint8_t* vec_2, const size_t vec_2_size) {
    uint8_t* vec = (uint8_t*)malloc(sizeof(uint8_t) * (vec_1_size + vec_2_size));
    memcpy(vec, vec_1, sizeof(uint8_t) * vec_1_size);
    memcpy(vec + sizeof(uint8_t) * vec_1_size, vec_2, sizeof(uint8_t) * vec_2_size);
    return vec;
}

uint8_t* appendzero(const uint8_t* data, const size_t data_size, const size_t size) {
    if (data_size < size) {
        uint8_t* zeroslice = (uint8_t*)malloc(sizeof(uint8_t) * (size - data_size));
        memset(zeroslice, 0, sizeof(uint8_t) * (size - data_size));
        uint8_t* new = concvec(zeroslice, size - data_size, data, data_size);
        free(zeroslice);
        return new;
    } else {
        uint8_t* new = (uint8_t*)malloc(sizeof(uint8_t) * data_size);
        memcpy(new, data, sizeof(uint8_t) * data_size);
        return new;
    }
}

uint8_t* removezero(const uint8_t* data, const size_t data_size, const size_t size) {
    uint8_t* new = (uint8_t*)malloc(sizeof(uint8_t) * size);
    if (data_size > size) {
        memcpy(new, data + (data_size - size), sizeof(uint8_t) * size);
    } else {
        memcpy(new, data, sizeof(data) * data_size);
    }
    return new;
}

uint8_t* append_remove_zero(const uint8_t* data, const size_t data_size, const size_t size) {
    if (data_size > size) {
        return removezero(data, data_size, size);
    }
    if (data_size < size) {
        return appendzero(data, data_size, size);
    }
    if (data_size == size) {
        uint8_t* new = (uint8_t*)malloc(sizeof(uint8_t) * data_size);
        memcpy(new, data, sizeof(uint8_t) * data_size);
        return new;
    }
}

void u32_to_byte_array(const uint32_t value, uint8_t byte_array[4]) {
    byte_array[0] = (value >> 24) & 0xFF;
    byte_array[1] = (value >> 16) & 0xFF;
    byte_array[2] = (value >> 8) & 0xFF;
    byte_array[3] = value & 0xFF;
}

void byte_array_to_u32(const uint8_t byte_array[4], uint32_t* value) {
    *value = 0;
    *value |= byte_array[0] << 24;
    *value |= byte_array[1] << 16;
    *value |= byte_array[2] << 8;
    *value |= byte_array[3];
}

void mpz_to_hex(const mpz_t mpz, char* hex) {
    mpz_get_str(hex, 16, mpz);
}

void hex_to_mpz(const char* hex, mpz_t* mpz) {
    mpz_set_str(*mpz, hex, 16);
}

uint8_t* mpz_to_byte_array(const mpz_t mpz, size_t* array_size) {
    size_t size = (mpz_sizeinbase(mpz, 2) + 7) / 8;
    *array_size = size;
    uint8_t* byte_array = (uint8_t*)malloc(sizeof(uint8_t) * size);
    mpz_export(byte_array, NULL, 1, sizeof(uint8_t), 1, 0, mpz);
    return byte_array;
}

void byte_array_to_mpz(const uint8_t* byte_array, const size_t byte_array_size, mpz_t* mpz) {
    mpz_import(*mpz, byte_array_size, 1, sizeof(uint8_t), 1, 0, byte_array);
}

uint8_t* pad_zero_positive(const uint8_t* mpz_byte_array, const size_t mpz_byte_array_size, int* pad) {
    int msb = (mpz_byte_array[0] >> 7) & 1;
    if (msb == 1) {
        *pad = 1;
        uint8_t* mpz_byte_array_pad = (uint8_t*)malloc(sizeof(uint8_t) * (mpz_byte_array_size + 1));
        memset(mpz_byte_array_pad, 0, sizeof(uint8_t) * 1);
        memcpy(mpz_byte_array_pad + 1, mpz_byte_array, mpz_byte_array_size);
        return mpz_byte_array_pad;
    } else {
        *pad = 0;
        uint8_t* mpz_byte_array_pad = (uint8_t*)malloc(sizeof(uint8_t) * mpz_byte_array_size);
        memcpy(mpz_byte_array_pad, mpz_byte_array, mpz_byte_array_size);
        return mpz_byte_array_pad;
    }
}

uint32_t rotate_left(const uint32_t num, const uint32_t shift) {
    return (num << shift) | (num >> (32 - shift));
}

uint32_t rotate_right(const uint32_t num, const uint32_t shift) {
    return (num >> shift) | (num << (32 - shift));
}

void to_be_bytes(const uint32_t value, uint8_t byte_array[4]) {
    byte_array[0] = (value >> 24) & 0xff;
    byte_array[1] = (value >> 16) & 0xff;
    byte_array[2] = (value >> 8) & 0xff;
    byte_array[3] = value & 0xff;
}

void from_be_bytes(const uint8_t* byte_array, uint32_t* value) {
    *value = 0;
    *value |= byte_array[0] << 24;
    *value |= byte_array[1] << 16;
    *value |= byte_array[2] << 8;
    *value |= byte_array[3];
}

char* byte_array_to_hex(const uint8_t* byte_array, const size_t byte_array_size) {
    char* hex_chars = "0123456789abcdef";
    char* hex_string = (char*)malloc(sizeof(char) * (2 * byte_array_size + 1));
    for (int i = 0; i < byte_array_size; i++) {
        hex_string[i * 2] = hex_chars[byte_array[i] >> 4];
        hex_string[i * 2 + 1] = hex_chars[byte_array[i] & 0x0F];
    }
    hex_string[byte_array_size * 2] = '\0';
    return hex_string;
}

uint8_t hex_to_byte(const char hex_char) {
    if (hex_char >= '0' && hex_char <= '9') {
        return hex_char - '0';
    } else if (hex_char >= 'a' && hex_char <= 'f') {
        return hex_char - 'a' + 10;
    } else if (hex_char >= 'A' && hex_char <= 'F') {
        return hex_char - 'A' + 10;
    } else {
        return 0;
    }
}

uint8_t* hex_to_byte_array(const char* hex_string, const size_t hex_string_size) {
    uint8_t* byte_array = (uint8_t*)malloc(sizeof(uint8_t) * (hex_string_size / 2));
    for (int i = 0; i < hex_string_size; i+=2) {
        uint8_t high_nibble = hex_to_byte(hex_string[i]);
        uint8_t low_nibble = hex_to_byte(hex_string[i + 1]);
        uint8_t byte = (high_nibble << 4) | low_nibble;
        byte_array[i / 2] = byte;
    }
    return byte_array;
}

uint8_t* xor_vector(const uint8_t* a, const uint8_t* b, const size_t size) {
    uint8_t* c = (uint8_t*)malloc(sizeof(uint8_t) * size);
    for (int i = 0; i < size; i++) {
        c[i] = a[i] ^ b[i];
    }
    return c;
}
