#include "smcryptoc/sm2.h"
#include "smcryptoc/sm3.h"

const char* ECC_N = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123";
const char* ECC_P = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF";
const char* ECC_G = "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0";
const char* ECC_A = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC";
const char* ECC_B = "28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93";

typedef struct Point {
    mpz_t x;
    mpz_t y;
    mpz_t z;
} Point;

typedef struct Signdata {
    uint8_t r[32];
    uint8_t s[32];
    size_t r_size;
    size_t s_size;
} Signdata;

void div_ceil(const mpz_t a, const mpz_t b, mpz_t result) {
    mpz_add(result, a, b);
    mpz_t mpz_1;
    mpz_init_set_ui(mpz_1, 1);
    mpz_sub(result, result, mpz_1);
    mpz_div(result, result, b);
    mpz_clear(mpz_1);
}

void submod(const mpz_t a, const mpz_t b, const mpz_t ecc_p, mpz_t result) {
    if (mpz_cmp(a, b) > 0) {
        mpz_sub(result, a, b);
        mpz_mod(result, result, ecc_p);
    } else {
        mpz_t d;
        mpz_init(d);
        mpz_sub(d, b, a);
        mpz_t e;
        mpz_init(e);
        div_ceil(d, ecc_p, e);
        mpz_mul(result, e, ecc_p);
        mpz_sub(result, result, d);
        mpz_clear(d);
        mpz_clear(e);
    }
}

VecU8* kdf(const VecU8* z, const size_t klen) {
    VecU8* c = init_vecu8();
    uint32_t ct = 0x00000001;
    size_t j = (klen + 31) / 32;
    for (size_t i = 0; i < j; i++) {
        VecU8* tmp = init_vecu8();
        push_vecu8_vecu8(tmp, z);
        VecU8* buf = init_vecu8();
        uint8_t ct_array[4];
        u32_to_byte_array(ct, ct_array);        
        unshift_vec_vecu8(buf, ct_array, 4);
        push_vecu8_vecu8(tmp, buf);

        destroy_vecu8(buf);
        char* hash = sm3_hash(tmp->data, tmp->len);
        destroy_vecu8(tmp);
        uint8_t* hash_byte_array = hex_to_byte_array(hash, 64);
        free(hash);
        if (i + 1 == j && klen % 32 != 0) {
            uint8_t* hash_byte_array_32 = (uint8_t*)malloc(sizeof(uint8_t) * (klen % 32));
            memcpy(hash_byte_array_32, hash_byte_array, sizeof(uint8_t) * (klen % 32));
            push_vec_vecu8(c, hash_byte_array_32, klen % 32);
            free(hash_byte_array_32);
        } else {
            push_vec_vecu8(c, hash_byte_array, 64);
        }
        free(hash_byte_array);
        ct += 1;
    }
    return c;
}

Point pubkey2point(const char* public_key) {
    mpz_t x, y, z;
    mpz_init(x); 
    mpz_init(y); 
    mpz_init(z);
    char public_key_l[65], public_key_r[65];
    strncpy(public_key_l, public_key, 64);
    strncpy(public_key_r, public_key + 64, 64);
    public_key_l[64] = '\0';
    public_key_r[64] = '\0';
    hex_to_mpz(public_key_l, &x);
    hex_to_mpz(public_key_r, &y);
    mpz_init_set_ui(z, 1);
    Point point;
    mpz_init(point.x);
    mpz_init(point.y);
    mpz_init(point.z);
    mpz_set(point.x, x);
    mpz_set(point.y, y);
    mpz_set(point.z, z);
    mpz_clear(z);
    mpz_clear(y);
    mpz_clear(x);
    return point;
}

Point double_point(const Point input) {
    mpz_t x1, y1, z1;
    mpz_init(x1);
    mpz_init(y1);
    mpz_init(z1);
    mpz_set(x1, input.x);
    mpz_set(y1, input.y);
    mpz_set(z1, input.z);
    mpz_t ecc_p;
    mpz_init(ecc_p);
    hex_to_mpz(ECC_P, &ecc_p);
    mpz_t t6, t2, t3, t4, t1, t5, z3, x3, y3;
    mpz_init(t6);
    mpz_init(t2);
    mpz_init(t3);
    mpz_init(t4);
    mpz_init(t1);
    mpz_init(t5);
    mpz_init(z3);
    mpz_init(x3);
    mpz_init(y3);
    mpz_mul(t6, z1, z1);
    mpz_mod(t6, t6, ecc_p);
    mpz_mul(t2, y1, y1);
    mpz_mod(t2, t2, ecc_p);
    mpz_add(t3, x1, t6);
    mpz_mod(t3, t3, ecc_p);
    submod(x1, t6, ecc_p, t4);
    mpz_mul(t1, t3, t4);
    mpz_mod(t1, t1, ecc_p);
    mpz_mul(t3, y1, z1);
    mpz_mod(t3, t3, ecc_p);
    mpz_t mpz_8;
    mpz_init_set_ui(mpz_8, 8);
    mpz_mul(t4, t2, mpz_8);
    mpz_mod(t4, t4, ecc_p);
    mpz_mul(t5, x1, t4);
    mpz_mod(t5, t5, ecc_p);
    mpz_t mpz_3;
    mpz_init_set_ui(mpz_3, 3);
    mpz_mul(t1, t1, mpz_3);
    mpz_mod(t1, t1, ecc_p);
    mpz_mul(t6, t6, t6);
    mpz_mod(t6, t6, ecc_p);
    mpz_t ecc_a;
    mpz_init(ecc_a);
    hex_to_mpz(ECC_A, &ecc_a);
    mpz_t ecc_a3;
    mpz_init(ecc_a3);
    mpz_add(ecc_a3, ecc_a, mpz_3);
    mpz_mod(ecc_a3, ecc_a3, ecc_p);
    mpz_mul(t6, ecc_a3, t6);
    mpz_mod(t6, t6, ecc_p);
    mpz_add(t1, t1, t6);
    mpz_mod(t1, t1, ecc_p);
    mpz_add(z3, t3, t3);
    mpz_mod(z3, z3, ecc_p);
    mpz_mul(t3, t1, t1);
    mpz_mod(t3, t3, ecc_p);
    mpz_mul(t2, t2, t4);
    mpz_mod(t2, t2, ecc_p);
    submod(t3, t5, ecc_p, x3);
    mpz_t mpz_2, mpz_1;
    mpz_init_set_ui(mpz_2, 2);
    mpz_init_set_ui(mpz_1, 1);
    mpz_t t5_mod_mpz_2;
    mpz_init(t5_mod_mpz_2);
    mpz_mod(t5_mod_mpz_2, t5, mpz_2);
    mpz_t tt;
    mpz_init(tt);
    if (mpz_cmp(t5_mod_mpz_2, mpz_1) == 0) {
        mpz_add(tt, t5, ecc_p);
        mpz_fdiv_q_2exp(tt, tt, 1);
        mpz_add(tt, t5, tt);
        submod(tt, t3, ecc_p, t4);
    } else {
        mpz_fdiv_q_2exp(tt, t5, 1);
        mpz_add(tt, tt, t5);
        submod(tt, t3, ecc_p, t4);
    }
    mpz_mul(t1, t1, t4);
    mpz_mod(t1, t1, ecc_p);
    submod(t1, t2, ecc_p, y3);
    Point point;
    mpz_init(point.x);
    mpz_init(point.y);
    mpz_init(point.z);
    mpz_set(point.x, x3);
    mpz_set(point.y, y3);
    mpz_set(point.z, z3);
    mpz_clear(x1);
    mpz_clear(y1);
    mpz_clear(z1);
    mpz_clear(ecc_p);
    mpz_clear(t6);
    mpz_clear(t2);
    mpz_clear(t3);
    mpz_clear(t4);
    mpz_clear(t1);
    mpz_clear(t5);
    mpz_clear(z3);
    mpz_clear(x3);
    mpz_clear(y3);
    mpz_clear(mpz_8);
    mpz_clear(mpz_3);
    mpz_clear(ecc_a);
    mpz_clear(ecc_a3);
    mpz_clear(mpz_2);
    mpz_clear(mpz_1);
    mpz_clear(t5_mod_mpz_2);
    mpz_clear(tt);
    return point;
}

Point add_point(const Point p1, const Point p2) {
    mpz_t x1, y1, z1, x2, y2;
    mpz_init(x1);
    mpz_init(y1);
    mpz_init(z1);
    mpz_init(x2);
    mpz_init(y2);
    mpz_set(x1, p1.x);
    mpz_set(y1, p1.y);
    mpz_set(z1, p1.z);
    mpz_set(x2, p2.x);
    mpz_set(y2, p2.y);
    mpz_t ecc_p;
    mpz_init(ecc_p);
    hex_to_mpz(ECC_P, &ecc_p);
    mpz_t t1, t2, t3, t4, t5, x3, y3, z3;
    mpz_init(t1);
    mpz_init(t2);
    mpz_init(t3);
    mpz_init(t4);
    mpz_init(t5);
    mpz_init(x3);
    mpz_init(y3);
    mpz_init(z3);
    mpz_mul(t1, z1, z1);
    mpz_mod(t1, t1, ecc_p);
    mpz_mul(t2, y2, z1);
    mpz_mod(t2, t2, ecc_p);
    mpz_mul(t3, x2, t1);
    mpz_mod(t3, t3, ecc_p);
    mpz_mul(t1, t1, t2);
    mpz_mod(t1, t1, ecc_p);
    submod(t3, x1, ecc_p, t2);
    mpz_add(t3, t3, x1);
    mpz_mod(t3, t3, ecc_p);
    mpz_mul(t4, t2, t2);
    mpz_mod(t4, t4, ecc_p);
    submod(t1, y1, ecc_p, t1);
    mpz_mul(z3, z1, t2);
    mpz_mod(z3, z3, ecc_p);
    mpz_mul(t2, t2, t4);
    mpz_mod(t2, t2, ecc_p);
    mpz_mul(t3, t3, t4);
    mpz_mod(t3, t3, ecc_p);
    mpz_mul(t5, t1, t1);
    mpz_mod(t5, t5, ecc_p);
    mpz_mul(t4, x1, t4);
    mpz_mod(t4, t4, ecc_p);
    submod(t5, t3, ecc_p, x3);
    mpz_mul(t2, y1, t2);
    mpz_mod(t2, t2, ecc_p);
    submod(t4, x3, ecc_p, t3);
    mpz_mul(t1, t1, t3);
    mpz_mod(t1, t1, ecc_p);
    submod(t1, t2, ecc_p, y3);
    Point point;
    mpz_init(point.x);
    mpz_init(point.y);
    mpz_init(point.z);
    mpz_set(point.x, x3);
    mpz_set(point.y, y3);
    mpz_set(point.z, z3);
    mpz_clear(x1);
    mpz_clear(y1);
    mpz_clear(z1);
    mpz_clear(x2);
    mpz_clear(y2);
    mpz_clear(ecc_p);
    mpz_clear(t1);
    mpz_clear(t2);
    mpz_clear(t3);
    mpz_clear(t4);
    mpz_clear(t5);
    mpz_clear(x3);
    mpz_clear(y3);
    mpz_clear(z3);
    return point;
}

Point convert_jacb_to_nor(const Point point) {
    mpz_t ecc_p;
    mpz_init(ecc_p);
    hex_to_mpz(ECC_P, &ecc_p);
    mpz_t x, y, z, z_1;
    mpz_init(x);
    mpz_init(y);
    mpz_init(z);
    mpz_init(z_1);
    mpz_set(x, point.x);
    mpz_set(y, point.y);
    mpz_set(z, point.z);
    mpz_set(z_1, z);
    mpz_t mpz_2;
    mpz_init_set_ui(mpz_2, 2);
    mpz_t z_inv;
    mpz_init(z_inv);
    mpz_t temp_1;
    mpz_init(temp_1);
    mpz_sub(temp_1, ecc_p, mpz_2);
    mpz_powm(z_inv, z, temp_1, ecc_p);
    mpz_t z_invsquar, z_invqube, x_new, y_new, z_new, mpz_1, mpz_0;
    mpz_init(z_invsquar);
    mpz_init(z_invqube);
    mpz_init(x_new);
    mpz_init(y_new);
    mpz_init(z_new);
    mpz_mul(z_invsquar, z_inv, z_inv);
    mpz_mod(z_invsquar, z_invsquar, ecc_p);
    mpz_mul(z_invqube, z_invsquar, z_inv);
    mpz_mod(z_invqube, z_invqube, ecc_p);
    mpz_mul(x_new, x, z_invsquar);
    mpz_mod(x_new, x_new, ecc_p);
    mpz_mul(y_new, y, z_invqube);
    mpz_mod(y_new, y_new, ecc_p);
    mpz_mul(z_new, z_1, z_inv);
    mpz_mod(z_new, z_new, ecc_p);
    mpz_init_set_ui(mpz_1, 1);
    mpz_init_set_ui(mpz_0, 0);
    Point result;
    mpz_init(result.x);
    mpz_init(result.y);
    mpz_init(result.z);
    if (mpz_cmp(z_new, mpz_1) == 0) {
        mpz_set(result.x, x_new);
        mpz_set(result.y, y_new);
        mpz_set(result.z, z_new);
    } else {
        mpz_set(result.x, mpz_0);
        mpz_set(result.y, mpz_0);
        mpz_set(result.z, mpz_0);
    }
    mpz_clear(ecc_p);
    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(z);
    mpz_clear(z_1);
    mpz_clear(mpz_2);
    mpz_clear(z_inv);
    mpz_clear(temp_1);
    mpz_clear(z_invsquar);
    mpz_clear(z_invqube);
    mpz_clear(x_new);
    mpz_clear(y_new);
    mpz_clear(z_new);
    mpz_clear(mpz_1);
    mpz_clear(mpz_0);
    return result;
}

Point kg(const mpz_t p_k, const char* p_point_str, const size_t p_point_str_len) {
    mpz_t k;
    mpz_init(k);
    mpz_set(k, p_k);
    char* point_str = (char*)malloc(sizeof(char) * p_point_str_len);
    memcpy(point_str, p_point_str, sizeof(char) * p_point_str_len);
    point_str = (char*)realloc(point_str, sizeof(char) * (p_point_str_len + 1));
    size_t point_str_len = p_point_str_len + 1;
    point_str[point_str_len - 1] = '1';
    char x_str[65], y_str[65];
    strncpy(x_str, point_str, 64);
    strncpy(y_str, point_str + 64, 64);
    x_str[64] = '\0';
    y_str[64] = '\0';
    char* z_str = (char*)malloc(sizeof(char) * (point_str_len - 128 + 1));
    strncpy(z_str, point_str + 128, point_str_len - 128);
    z_str[point_str_len - 128] = '\0';
    free(point_str);
    mpz_t x, y, z;
    mpz_init(x);
    mpz_init(y);
    mpz_init(z);
    hex_to_mpz(x_str, &x);
    hex_to_mpz(y_str, &y);
    hex_to_mpz(z_str, &z);
    free(z_str);
    Point point;
    mpz_init(point.x);
    mpz_init(point.y);
    mpz_init(point.z);
    mpz_set(point.x, x);
    mpz_set(point.y, y);
    mpz_set(point.z, z);
    char* mask_str = "8000000000000000000000000000000000000000000000000000000000000000";
    mpz_t mask;
    mpz_init(mask);
    hex_to_mpz(mask_str, &mask);
    Point temp;
    mpz_init(temp.x);
    mpz_init(temp.y);
    mpz_init(temp.z);
    mpz_set(temp.x, point.x);
    mpz_set(temp.y, point.y);
    mpz_set(temp.z, point.z);
    int flag = 0;
    mpz_t mpz_0;
    mpz_init_set_ui(mpz_0, 0);
    for (int i = 0; i < (64 * 4); i++) {
        if (flag == 1) {
            Point new_temp = double_point(temp);
            mpz_set(temp.x, new_temp.x);
            mpz_set(temp.y, new_temp.y);
            mpz_set(temp.z, new_temp.z);
            mpz_clear(new_temp.x);
            mpz_clear(new_temp.y);
            mpz_clear(new_temp.z);
        }
        mpz_t k_and_mask;
        mpz_init(k_and_mask);
        mpz_and(k_and_mask, k, mask);

        if (mpz_cmp(k_and_mask, mpz_0) != 0) {
            if (flag == 1) {
                Point new_temp = add_point(temp, point);
                mpz_set(temp.x, new_temp.x);
                mpz_set(temp.y, new_temp.y);
                mpz_set(temp.z, new_temp.z);
                mpz_clear(new_temp.x);
                mpz_clear(new_temp.y);
                mpz_clear(new_temp.z);
            } else {
                flag = 1;
                mpz_set(temp.x, point.x);
                mpz_set(temp.y, point.y);
                mpz_set(temp.z, point.z);
            }
        }
        mpz_mul_2exp(k, k, 1);
        mpz_clear(k_and_mask);
    }
    Point kg_result = convert_jacb_to_nor(temp);
    mpz_clear(temp.x);
    mpz_clear(temp.y);
    mpz_clear(temp.z);
    mpz_clear(point.x);
    mpz_clear(point.y);
    mpz_clear(point.z);
    mpz_clear(k);
    mpz_clear(x);
    mpz_clear(y);
    mpz_clear(z);
    mpz_clear(mask);
    mpz_clear(mpz_0);
    return kg_result;
}

char* gen_sk() {
    char* d = random_hex(64);
    return d;
}

char* pk_from_sk(const char* private_key) {
    mpz_t mpz_pk;
    mpz_init(mpz_pk);
    hex_to_mpz(private_key, &mpz_pk);
    Point p = kg(mpz_pk, ECC_G, strlen(ECC_G));
    char* hex_x = (char*)malloc(sizeof(char) * 65);
    char* hex_y = (char*)malloc(sizeof(char) * 65);
    mpz_to_hex(p.x, hex_x);
    mpz_to_hex(p.y, hex_y);
    hex_x[64] = '\0';
    hex_y[64] = '\0';
    mpz_clear(mpz_pk);
    char* hex = format_hex(hex_x, hex_y);
    free(hex_x);
    free(hex_y);
    mpz_clear(p.x);
    mpz_clear(p.y);
    mpz_clear(p.z);
    return hex;
}

uint8_t* asn1_encode_rs(const Signdata sign_data, size_t* size) {
    uint8_t* r_bytes = (uint8_t*)malloc(sizeof(uint8_t) * sign_data.r_size);
    uint8_t* s_bytes = (uint8_t*)malloc(sizeof(uint8_t) * sign_data.s_size);
    memcpy(r_bytes, sign_data.r, sizeof(uint8_t) * sign_data.r_size);
    memcpy(s_bytes, sign_data.s, sizeof(uint8_t) * sign_data.s_size);
    int pad_r, pad_s;
    uint8_t* r_bytes_new = pad_zero_positive(r_bytes, sign_data.r_size, &pad_r);
    uint8_t* s_bytes_new = pad_zero_positive(s_bytes, sign_data.s_size, &pad_s);
    size_t r_bytes_new_size, s_bytes_new_size;
    if (pad_r) {
        r_bytes_new_size = sign_data.r_size + 1;
    } else {
        r_bytes_new_size = sign_data.r_size;
    }
    if (pad_s) {
        s_bytes_new_size = sign_data.s_size + 1;
    } else {
        s_bytes_new_size = sign_data.s_size;
    }
    VecU8* result = init_vecu8();
    push_vecu8(result, 0x30);
    push_vecu8(result, r_bytes_new_size + s_bytes_new_size + 4);
    push_vecu8(result, 0x02);
    push_vecu8(result, r_bytes_new_size);
    push_vec_vecu8(result, r_bytes_new, r_bytes_new_size);
    push_vecu8(result, 0x02);
    push_vecu8(result, s_bytes_new_size);
    push_vec_vecu8(result, s_bytes_new, s_bytes_new_size);
    uint8_t* asn1_bytes_rs = (uint8_t*)malloc(sizeof(uint8_t) * result->len);
    memcpy(asn1_bytes_rs, result->data, sizeof(uint8_t) * result->len);
    *size = result->len;
    destroy_vecu8(result);
    free(r_bytes_new);
    free(s_bytes_new);
    free(r_bytes);
    free(s_bytes);
    return asn1_bytes_rs;
}

Signdata asn1_decode_rs(const uint8_t* asn1_bytes_rs) {
    size_t r_bytes_size = (size_t)asn1_bytes_rs[3];
    uint8_t* r_bytes = (uint8_t*)malloc(sizeof(uint8_t) * r_bytes_size);
    memcpy(r_bytes, asn1_bytes_rs + 4, sizeof(uint8_t) * r_bytes_size);
    size_t s_bytes_size = (size_t)asn1_bytes_rs[4 + r_bytes_size + 2 - 1];
    uint8_t* s_bytes = (uint8_t*)malloc(sizeof(uint8_t) * s_bytes_size);
    memcpy(s_bytes, asn1_bytes_rs + 4 + r_bytes_size + 2, sizeof(uint8_t) * s_bytes_size);
    uint8_t* r_bytes_new = NULL;
    uint8_t* s_bytes_new = NULL;
    size_t r_bytes_size_new = 0;
    size_t s_bytes_size_new = 0;
    if (r_bytes[0] == 0) {
        r_bytes_new = (uint8_t*)malloc(sizeof(uint8_t) * (r_bytes_size - 1));
        memcpy(r_bytes_new, r_bytes + 1, sizeof(uint8_t) * (r_bytes_size - 1));
        r_bytes_size_new = r_bytes_size - 1;
    } else {
        r_bytes_new = (uint8_t*)malloc(sizeof(uint8_t) * r_bytes_size);
        memcpy(r_bytes_new, r_bytes, sizeof(uint8_t) * r_bytes_size);
        r_bytes_size_new = r_bytes_size;
    }
    if (s_bytes[0] == 0) {
        s_bytes_new = (uint8_t*)malloc(sizeof(uint8_t) * (s_bytes_size - 1));
        memcpy(s_bytes_new, s_bytes + 1, sizeof(uint8_t) * (s_bytes_size - 1));
        s_bytes_size_new = s_bytes_size - 1;
    } else {
        s_bytes_new = (uint8_t*)malloc(sizeof(uint8_t) * s_bytes_size);
        memcpy(s_bytes_new, s_bytes, sizeof(uint8_t) * s_bytes_size);
        s_bytes_size_new = s_bytes_size;
    }
    Signdata sign_data;
    memset(sign_data.r, 0, sizeof(uint8_t) * 32);
    memset(sign_data.s, 0, sizeof(uint8_t) * 32);
    memcpy(sign_data.r, r_bytes_new, sizeof(uint8_t) * r_bytes_size_new);
    memcpy(sign_data.s, s_bytes_new, sizeof(uint8_t) * s_bytes_size_new);
    sign_data.r_size = r_bytes_size_new;
    sign_data.s_size = s_bytes_size_new;
    free(r_bytes_new);
    free(s_bytes_new);
    free(r_bytes);
    free(s_bytes);
    return sign_data;
}

uint8_t* sign_raw(const uint8_t* data, size_t data_len, const char* private_key, size_t* size) {
    char* data_hex = byte_array_to_hex(data, data_len);
    mpz_t e;
    mpz_init(e);
    hex_to_mpz(data_hex, &e);
    mpz_t d;
    mpz_init(d);
    hex_to_mpz(private_key, &d);
    char* k_hex = random_hex(64);
    mpz_t k;
    mpz_init(k);
    hex_to_mpz(k_hex, &k);
    mpz_t k1;
    mpz_init(k1);
    mpz_set(k1, k);
    Point p1 = kg(k, ECC_G, strlen(ECC_G));
    mpz_t mpz_ecc_n;
    mpz_init(mpz_ecc_n);
    hex_to_mpz(ECC_N, &mpz_ecc_n);
    mpz_t r;
    mpz_init(r);
    mpz_add(r, e, p1.x);
    mpz_mod(r, r, mpz_ecc_n);
    mpz_t mpz_1, mpz_2;
    mpz_init_set_ui(mpz_1, 1);
    mpz_init_set_ui(mpz_2, 2);
    mpz_t d_1;
    mpz_init(d_1);
    mpz_t base_1;
    mpz_init(base_1);
    mpz_add(base_1, d, mpz_1);
    mpz_t exp_1;
    mpz_init(exp_1);
    mpz_sub(exp_1, mpz_ecc_n, mpz_2);
    mpz_t mod_1;
    mpz_init(mod_1);
    mpz_set(mod_1, mpz_ecc_n);
    mpz_powm(d_1, base_1, exp_1, mod_1);
    mpz_t s;
    mpz_init(s);
    mpz_add(s, k1, r);
    mpz_mul(s, s, d_1);
    mpz_sub(s, s, r);
    mpz_mod(s, s, mpz_ecc_n);
    Signdata sign_data;
    size_t r_byte_array_size, s_byte_array_size;
    uint8_t* r_byte_array = mpz_to_byte_array(r, &r_byte_array_size);
    uint8_t* s_byte_array = mpz_to_byte_array(s, &s_byte_array_size);
    memcpy(sign_data.r, r_byte_array, sizeof(uint8_t) * r_byte_array_size);
    memcpy(sign_data.s, s_byte_array, sizeof(uint8_t) * s_byte_array_size);
    sign_data.r_size = r_byte_array_size;
    sign_data.s_size = s_byte_array_size;
    uint8_t* result = asn1_encode_rs(sign_data, size);
    free(r_byte_array);
    free(s_byte_array);
    mpz_clear(p1.x);
    mpz_clear(p1.y);
    mpz_clear(p1.z);
    mpz_clear(e);
    mpz_clear(d);
    mpz_clear(k);
    mpz_clear(k1);
    mpz_clear(mpz_ecc_n);
    mpz_clear(r);
    mpz_clear(mpz_1);
    mpz_clear(mpz_2);
    mpz_clear(d_1);
    mpz_clear(base_1);
    mpz_clear(exp_1);
    mpz_clear(mod_1);
    mpz_clear(s);
    free(k_hex);
    free(data_hex);
    return result;
}

int verify_raw(const uint8_t* data, const size_t data_len, const uint8_t* sign_bytes, const char* public_key) {
    Signdata sign_data = asn1_decode_rs(sign_bytes);
    mpz_t r, s;
    mpz_init(r);
    mpz_init(s);
    byte_array_to_mpz(sign_data.r, sign_data.r_size, &r);
    byte_array_to_mpz(sign_data.s, sign_data.s_size, &s);
    mpz_t e;
    mpz_init(e);
    byte_array_to_mpz(data, data_len, &e);
    mpz_t ecc_n;
    mpz_init(ecc_n);
    hex_to_mpz(ECC_N, &ecc_n);
    mpz_t t;
    mpz_init(t);
    mpz_add(t, r, s);
    mpz_mod(t, t, ecc_n);
    mpz_t mpz_0;
    mpz_init_set_ui(mpz_0, 0);
    int result = 0;
    if (mpz_cmp(t, mpz_0) == 0) {
        result = 0;
    } else {
        Point p1 = kg(s, ECC_G, strlen(ECC_G));
        Point p2 = kg(t, public_key, strlen(public_key));
        if (mpz_cmp(p1.x, p2.x) == 0 && mpz_cmp(p1.y, p2.y) == 0 && mpz_cmp(p1.z, p2.z) == 0) {
            Point p1_new = double_point(p1);
            mpz_set(p1.x, p1_new.x);
            mpz_set(p1.y, p1_new.y);
            mpz_set(p1.z, p1_new.z);
            mpz_clear(p1_new.x);
            mpz_clear(p1_new.y);
            mpz_clear(p1_new.z);
        } else {
            Point p1_new = add_point(p1, p2);
            mpz_set(p1.x, p1_new.x);
            mpz_set(p1.y, p1_new.y);
            mpz_set(p1.z, p1_new.z);
            mpz_clear(p1_new.x);
            mpz_clear(p1_new.y);
            mpz_clear(p1_new.z);
            Point p1_new2 = convert_jacb_to_nor(p1);
            mpz_set(p1.x, p1_new2.x);
            mpz_set(p1.y, p1_new2.y);
            mpz_set(p1.z, p1_new2.z);
            mpz_clear(p1_new2.x);
            mpz_clear(p1_new2.y);
            mpz_clear(p1_new2.z);
        }
        mpz_t x;
        mpz_init(x);
        mpz_set(x, p1.x);
        mpz_t rc;
        mpz_init(rc);
        mpz_add(rc, e, x);
        mpz_mod(rc, rc, ecc_n);
        if (mpz_cmp(r, rc) == 0) {
            result = 1;
        } else {
            result = 0;
        }
        mpz_clear(x);
        mpz_clear(rc);
        mpz_clear(p1.x);
        mpz_clear(p1.y);
        mpz_clear(p1.z);
        mpz_clear(p2.x);
        mpz_clear(p2.y);
        mpz_clear(p2.z);
    }
    mpz_clear(r);
    mpz_clear(s);
    mpz_clear(e);
    mpz_clear(ecc_n);
    mpz_clear(t);
    mpz_clear(mpz_0);
    return result;
}

uint8_t* encrypt_raw(const uint8_t* data, const size_t data_size, const char* public_key, size_t* size) {
    char* k_hex = random_hex(64);
    mpz_t k_mpz;
    mpz_init(k_mpz);
    hex_to_mpz(k_hex, &k_mpz);
    Point c1xyz = kg(k_mpz, ECC_G, strlen(ECC_G));
    size_t c1xyz_x_bytes_size, c1xyz_y_bytes_size;
    uint8_t* c1xyz_x_bytes = mpz_to_byte_array(c1xyz.x, &c1xyz_x_bytes_size);
    uint8_t* c1xyz_y_bytes = mpz_to_byte_array(c1xyz.y, &c1xyz_y_bytes_size);
    uint8_t* c1xyz_x_bytes_pad = appendzero(c1xyz_x_bytes, c1xyz_x_bytes_size, 32);
    uint8_t* c1xyz_y_bytes_pad = appendzero(c1xyz_y_bytes, c1xyz_y_bytes_size, 32);
    uint8_t* c1 = concvec(c1xyz_x_bytes_pad, 32, c1xyz_y_bytes_pad, 32);
    size_t c1_size = 64;
    Point xy = kg(k_mpz, public_key, strlen(public_key));
    size_t x2_size, y2_size;
    uint8_t* x2 = mpz_to_byte_array(xy.x, &x2_size);
    uint8_t* y2 = mpz_to_byte_array(xy.y, &y2_size);
    uint8_t* x2_pad = appendzero(x2, x2_size, 32);
    uint8_t* y2_pad = appendzero(y2, y2_size, 32);
    size_t x2_pad_size = 32;
    size_t y2_pad_size = 32;
    uint8_t* xyv = concvec(x2_pad, x2_pad_size, y2_pad, y2_pad_size);
    VecU8* xyv_vecu8 = init_vecu8();
    push_vec_vecu8(xyv_vecu8, xyv, 64);
    VecU8* t_vecu8 = kdf(xyv_vecu8, data_size);
    mpz_t mpz_data, mpz_t_;
    mpz_init(mpz_data);
    mpz_init(mpz_t_);
    byte_array_to_mpz(data, data_size, &mpz_data);
    byte_array_to_mpz(t_vecu8->data, t_vecu8->len, &mpz_t_);
    mpz_t c2_mpz;
    mpz_init(c2_mpz);
    mpz_xor(c2_mpz, mpz_data, mpz_t_);
    size_t c2_size;
    uint8_t* c2 = mpz_to_byte_array(c2_mpz, &c2_size);
    uint8_t* c2_pad = appendzero(c2, c2_size, data_size);
    size_t c2_pad_size = data_size;
    uint8_t* x2_data = concvec(x2_pad, x2_pad_size, data, data_size);
    size_t x2_data_size = x2_size + data_size;
    uint8_t* h = concvec(x2_data, x2_data_size, y2, y2_size);
    size_t h_size = x2_data_size + y2_size;
    char* h_sm3 = sm3_hash(h, h_size);
    uint8_t* c3 = hex_to_byte_array(h_sm3, strlen(h_sm3));
    uint8_t* c1_c3 = concvec(c1, c1_size, c3, strlen(h_sm3) / 2);
    size_t c1_c3_size = c1_size + strlen(h_sm3) / 2;
    uint8_t* cipher = concvec(c1_c3, c1_c3_size, c2_pad, c2_pad_size);
    size_t cipher_size = c1_c3_size + c2_size;
    *size = cipher_size;
    mpz_clear(k_mpz);
    mpz_clear(mpz_data);
    mpz_clear(mpz_t_);
    mpz_clear(c2_mpz);
    mpz_clear(c1xyz.x);
    mpz_clear(c1xyz.y);
    mpz_clear(c1xyz.z);
    mpz_clear(xy.x);
    mpz_clear(xy.y);
    mpz_clear(xy.z);
    destroy_vecu8(xyv_vecu8);
    destroy_vecu8(t_vecu8);
    free(c1_c3);
    free(c3);
    free(h);
    free(x2_data);
    free(c2_pad);
    free(c2);
    free(x2);
    free(y2);
    free(x2_pad);
    free(y2_pad);
    free(xyv);
    free(c1xyz_x_bytes);
    free(c1xyz_y_bytes);
    free(c1xyz_x_bytes_pad);
    free(c1xyz_y_bytes_pad);
    free(c1);
    free(k_hex);
    free(h_sm3);
    return cipher;
}

uint8_t* decrypt_raw(const uint8_t* cipher, const size_t cipher_size, const char* private_key, size_t* size) {
    size_t c1_size = 64;
    uint8_t* c1 = (uint8_t*)malloc(sizeof(uint8_t) * c1_size);
    memcpy(c1, cipher, sizeof(uint8_t) * c1_size);
    size_t c2_size = cipher_size - 96;
    uint8_t* c2 = (uint8_t*)malloc(sizeof(uint8_t) * c2_size);
    memcpy(c2, cipher + 96, sizeof(uint8_t) * c2_size);
    mpz_t mpz_sk;
    mpz_init(mpz_sk);
    hex_to_mpz(private_key, &mpz_sk);
    char* c1_hex = byte_array_to_hex(c1, 64);
    Point xy = kg(mpz_sk, c1_hex, strlen(c1_hex));
    size_t x_size, y_size;
    uint8_t* x = mpz_to_byte_array(xy.x, &x_size);
    uint8_t* y = mpz_to_byte_array(xy.y, &y_size);
    uint8_t* x_pad = appendzero(x, x_size, 32);
    uint8_t* y_pad = appendzero(y, y_size, 32);
    uint8_t* xyv = concvec(x_pad, 32, y_pad, 32);
    size_t xyv_size = 64;
    VecU8* xyv_vecu8 = init_vecu8();
    push_vec_vecu8(xyv_vecu8, xyv, xyv_size);
    VecU8* t_vecu8 = kdf(xyv_vecu8, c2_size);
    mpz_t mpz_t_, mpz_c2, mpz_c2_xor_t;
    mpz_init(mpz_t_);
    mpz_init(mpz_c2);
    mpz_init(mpz_c2_xor_t);
    byte_array_to_mpz(c2, c2_size, &mpz_c2);
    byte_array_to_mpz(t_vecu8->data, t_vecu8->len, &mpz_t_);
    mpz_xor(mpz_c2_xor_t, mpz_c2, mpz_t_);
    uint8_t* result = mpz_to_byte_array(mpz_c2_xor_t, size);
    mpz_clear(mpz_t_); mpz_clear(mpz_c2); mpz_clear(mpz_c2_xor_t); mpz_clear(mpz_sk);
    destroy_vecu8(t_vecu8); destroy_vecu8(xyv_vecu8); 
    mpz_clear(xy.x); mpz_clear(xy.y); mpz_clear(xy.z);
    free(xyv); free(x); free(y); free(x_pad); free(y_pad); free(c1); free(c2); free(c1_hex);
    return result;
}
