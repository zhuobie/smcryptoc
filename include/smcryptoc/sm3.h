#ifndef SM3_H
#define SM3_H

#include "smcryptoc/utils.h"

char* sm3_hash(const uint8_t* p_msg, const size_t p_msg_size);

#endif