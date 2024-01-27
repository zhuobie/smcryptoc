#include "smcryptoc/sm3.h"

uint32_t sm3_ff_j(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t j) {
    uint32_t ret = 0;
    if (j < 16) {
        ret = x ^ y ^ z;
    } else if (16 <= j && j < 64) {
        ret = (x & y) | (x & z) | (y & z);
    }
    return ret;
}

uint32_t sm3_gg_j(const uint32_t x, const uint32_t y, const uint32_t z, const uint32_t j) {
    uint32_t ret = 0;
    if (j < 16) {
        ret = x ^ y ^ z;
    } else if (16 <= j && j < 64) {
        ret = (x & y) | (~x & z);
    }
    return ret;
}

uint32_t sm3_p_0(const uint32_t x) {
    return x ^ rotate_left(x, 9) ^ rotate_left(x, 17);
}

uint32_t sm3_p_1(const uint32_t x) {
    return x ^ rotate_left(x, 15) ^ rotate_left(x, 23);
}

uint32_t* sm3_cf(const uint32_t* v_i, const uint32_t* b_i) {
    uint32_t t_j[] = {
        2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
        2043430169, 2043430169, 2043430169, 2043430169, 2043430169, 2043430169,
        2043430169, 2043430169, 2043430169, 2043430169, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042, 2055708042, 2055708042,
        2055708042, 2055708042, 2055708042, 2055708042
    };
    uint32_t w[68];
    memset(w, 0, sizeof(uint32_t) * 68);
    for (int i = 0; i < 16; i++) {
        uint32_t weight = 0x1000000;
        uint32_t data = 0;
        for (int k = (i * 4); k < (i * 4 + 4); k++) {
            data += (b_i[k] * weight);
            weight /= 0x100;
        }
        w[i] = data;
    }
    for (int j = 16; j < 68; j++) {
        w[j] = sm3_p_1(w[j - 16] ^ w[j - 9] ^ rotate_left(w[j - 3], 15)) ^ rotate_left(w[j - 13], 7) ^ w[j - 6];
    }
    uint32_t w_1[64];
    memset(w_1, 0, sizeof(uint32_t) * 64);
    for (int j = 0; j < 64; j++) {
        w_1[j] = w[j] ^ w[j + 4];
    }
    uint32_t a = v_i[0];
    uint32_t b = v_i[1];
    uint32_t c = v_i[2];
    uint32_t d = v_i[3];
    uint32_t e = v_i[4];
    uint32_t f = v_i[5];
    uint32_t g = v_i[6];
    uint32_t h = v_i[7];
    for (int j = 0; j < 64; j++) {
        uint32_t ss_1 = rotate_left((rotate_left(a, 12) + e + rotate_left(t_j[j], j)) & 0xffffffff, 7);
        uint32_t ss_2 = ss_1 ^ rotate_left(a, 12);
        uint32_t tt_1 = (sm3_ff_j(a, b, c, j) + d + ss_2 + w_1[j]) & 0xffffffff;
        uint32_t tt_2 = (sm3_gg_j(e, f, g, j) + h + ss_1 + w[j]) & 0xffffffff;
        d = c;
        c = rotate_left(b, 9);
        b = a;
        a = tt_1;
        h = g;
        g = rotate_left(f, 19);
        f = e;
        e = sm3_p_0(tt_2);
        a = a & 0xffffffff;
        b = b & 0xffffffff;
        c = c & 0xffffffff;
        d = d & 0xffffffff;
        e = e & 0xffffffff;
        f = f & 0xffffffff;
        g = g & 0xffffffff;
        h = h & 0xffffffff;
    }
    uint32_t v_j[] = {a, b, c, d, e, f, g, h};
    uint32_t* cf = (uint32_t*)malloc(sizeof(uint32_t) * 8);
    for (int i = 0; i < 8; i++) {
        cf[i] = v_j[i] ^ v_i[i];
    }
    return cf;
}

char* sm3_hash(const uint8_t* p_msg, const size_t p_msg_size) {
    VecU8* msg = init_vecu8();
    push_vec_vecu8(msg, p_msg, p_msg_size);
    uint32_t iv[] = {
        1937774191, 1226093241, 388252375, 3666478592,
        2842636476, 372324522, 3817729613, 2969243214
    };
    uint32_t len1 = msg->len;
    uint32_t reverse1 = len1 % 64;
    push_vecu8(msg, 0x80);
    reverse1 += 1;
    uint32_t range_end = 56;
    if (reverse1 > range_end) {
        range_end += 64;
    }
    for (uint32_t i = reverse1; i < range_end; i++) {
        push_vecu8(msg, 0x00);
    }
    size_t bit_length = len1 * 8;
    size_t bit_length_str[] = {0, 0, 0, 0, 0, 0, 0, 0};
    bit_length_str[0] = bit_length % 0x100;
    for (int i = 0; i < 7; i++) {
        bit_length /= 0x100;
        bit_length_str[i + 1] = bit_length % 0x100;
    }
    for (int i = 0; i < 8; i++) {
        push_vecu8(msg, (uint8_t)bit_length_str[7 - i]);
    }
    size_t group_count = round((double)(msg->len) / (double)64);

    uint32_t** b = (uint32_t**)malloc(group_count * sizeof(uint32_t*));
    for (int i = 0; i < group_count; i++) {
        b[i] = (uint32_t*)malloc(sizeof(uint32_t) * 64);
        for (int j = 0; j < 64; j++) {
            b[i][j] = msg->data[i * 64 + j];
        }
    }
    uint32_t** v = (uint32_t**)malloc((group_count + 1) * sizeof(uint32_t*));
    v[0] = (uint32_t*)malloc(sizeof(uint32_t) * 8);
    memcpy(v[0], iv, sizeof(uint32_t) * 8);
    for (int i = 0; i < group_count; i++) {
        v[i + 1] = (uint32_t*)malloc(sizeof(uint32_t) * 8);
        uint32_t* cf = sm3_cf(v[i], b[i]);
        for (int j = 0; j < 8; j++) {
            v[i + 1][j] = cf[j];
        }
        free(cf);
    }

    uint32_t y[8];
    for (int i = 0; i < 8; i++) {
        y[i] = v[group_count][i];
    }

    for (int i = 0; i < group_count + 1; i++) {
        free(v[i]);
    }
    free(v);
    for (int i = 0; i < group_count; i++) {
        free(b[i]);
    }
    free(b);
    char* result = (char*)malloc(sizeof(char) * 65);
    result[0] = '\0';
    memset(result, 0, sizeof(char) * 65);
    for (int i = 0; i < 8; i++) {
        uint8_t byte_array[4];
        memset(byte_array, 0, sizeof(uint8_t) * 4);
        u32_to_byte_array(y[i], byte_array);
        char* hex = byte_array_to_hex(byte_array, 4);
        strcat(result, hex);
        free(hex);
    }
    destroy_vecu8(msg);
    return result;

}
