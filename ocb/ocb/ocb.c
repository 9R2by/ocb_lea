#include "ocb.h"


static inline uint8_t leftShift(uint8_t index, uint8_t shift, const uint8_t *array) {
    return array[index] << shift;
}

static inline uint8_t rightShift(uint8_t index, uint8_t shift, const uint8_t *array) {
    return array[index] >> shift;
}

void xor(uint8_t arr_out[16], const uint8_t arr_1[16], const uint8_t arr_2[16]) {
    arr_out[0] = arr_1[0] ^ arr_2[0];
    arr_out[1] = arr_1[1] ^ arr_2[1];
    arr_out[2] = arr_1[2] ^ arr_2[2];
    arr_out[3] = arr_1[3] ^ arr_2[3];
    arr_out[4] = arr_1[4] ^ arr_2[4];
    arr_out[5] = arr_1[5] ^ arr_2[5];
    arr_out[6] = arr_1[6] ^ arr_2[6];
    arr_out[7] = arr_1[7] ^ arr_2[7];
    arr_out[8] = arr_1[8] ^ arr_2[8];
    arr_out[9] = arr_1[9] ^ arr_2[9];
    arr_out[10] = arr_1[10] ^ arr_2[10];
    arr_out[11] = arr_1[11] ^ arr_2[11];
    arr_out[12] = arr_1[12] ^ arr_2[12];
    arr_out[13] = arr_1[13] ^ arr_2[13];
    arr_out[14] = arr_1[14] ^ arr_2[14];
    arr_out[15] = arr_1[15] ^ arr_2[15];
}


void double_func(uint8_t arr_out[16], const uint8_t arr_in[16]) {
    uint8_t s0 = arr_in[0];
    if (s0 == 0) {
        arr_out[0] = (arr_in[0] << 1) | (arr_in[1] >> 7);
        arr_out[1] = (arr_in[1] << 1) | (arr_in[2] >> 7);
        arr_out[2] = (arr_in[2] << 1) | (arr_in[3] >> 7);
        arr_out[3] = (arr_in[3] << 1) | (arr_in[4] >> 7);
        arr_out[4] = (arr_in[4] << 1) | (arr_in[5] >> 7);
        arr_out[5] = (arr_in[5] << 1) | (arr_in[6] >> 7);
        arr_out[6] = (arr_in[6] << 1) | (arr_in[7] >> 7);
        arr_out[7] = (arr_in[7] << 1) | (arr_in[8] >> 7);
        arr_out[8] = (arr_in[8] << 1) | (arr_in[9] >> 7);
        arr_out[9] = (arr_in[9] << 1) | (arr_in[10] >> 7);
        arr_out[10] = (arr_in[10] << 1) | (arr_in[11] >> 7);
        arr_out[11] = (arr_in[11] << 1) | (arr_in[12] >> 7);
        arr_out[12] = (arr_in[12] << 1) | (arr_in[13] >> 7);
        arr_out[13] = (arr_in[13] << 1) | (arr_in[14] >> 7);
        arr_out[14] = (arr_in[14] << 1) | (arr_in[15] >> 7);
    } else {
        arr_out[0] = (arr_in[0] << 1) | (arr_in[1] >> 7);
        arr_out[1] = (arr_in[1] << 1) | (arr_in[2] >> 7);
        arr_out[2] = (arr_in[2] << 1) | (arr_in[3] >> 7);
        arr_out[3] = (arr_in[3] << 1) | (arr_in[4] >> 7);
        arr_out[4] = (arr_in[4] << 1) | (arr_in[5] >> 7);
        arr_out[5] = (arr_in[5] << 1) | (arr_in[6] >> 7);
        arr_out[6] = (arr_in[6] << 1) | (arr_in[7] >> 7);
        arr_out[7] = (arr_in[7] << 1) | (arr_in[8] >> 7);
        arr_out[8] = (arr_in[8] << 1) | (arr_in[9] >> 7);
        arr_out[9] = (arr_in[9] << 1) | (arr_in[10] >> 7);
        arr_out[10] = (arr_in[10] << 1) | (arr_in[11] >> 7);
        arr_out[11] = (arr_in[11] << 1) | (arr_in[12] >> 7);
        arr_out[12] = (arr_in[12] << 1) | (arr_in[13] >> 7);
        arr_out[13] = (arr_in[13] << 1) | (arr_in[14] >> 7);
        arr_out[14] = (arr_in[14] << 1) | (arr_in[15] >> 7);
        arr_out[15] = (arr_in[15] << 1) ^ ((s0 >> 7) * 0x87);
    }
}


static inline void double_trailings(uint8_t arr[16], uint32_t trailing_zeroes) {
    for (uint32_t i = trailing_zeroes; i != 0; i--)
        double_func(arr, arr);
}

int ocb_enc(uint8_t *C, uint8_t *P, size_t p,uint8_t *tmp,
             uint8_t *L_dollar, uint8_t *stretch, uint8_t *offset,
             uint8_t *sum, uint8_t *tag, uint32_t b_and, uint32_t b_div) {
    if (b_and != 0) {
        for (uint8_t i = 0; i < 16; i++) {
            uint8_t l = leftShift(i + b_div, b_and, stretch);
            uint8_t r = rightShift(i + b_div + 1, 8 - b_and, stretch);
            offset[i] = l | r;
        }
    } else {
        for (uint8_t i = 0; i < 16; i++) {
            offset[i] = stretch[i + b_div];
        }
    }
    memset(sum, 0, 16);
    for (size_t i = 1; i <= p; i++) {
        double_func(tmp, L_dollar);
        double_trailings(tmp, __builtin_ctz(i));
        xor(offset, offset, tmp);
        xor(tmp, offset, P);
        lea_encrypt(tmp, tmp);
        xor(C, offset, tmp);
        xor(sum, P, sum);
        P+=16;
        C+=16;
    }

    xor(tmp, sum, offset);
    xor(tmp, tmp, L_dollar);
    lea_encrypt(tmp, tag);
    //hash without A = 0
    memset(tmp, 0, 16);
    xor(tag, tmp, tag);
    memcpy(C, tag, 16);
    return 0;
}


int ocb_dec(uint8_t *P, uint8_t *C, size_t c,
            uint8_t *tmp, uint8_t *L_dollar,
            uint8_t *stretch, uint8_t *offset, uint8_t *sum, uint8_t *tag, uint32_t b_and, uint32_t b_div) {
    if (b_and != 0) {
        for (uint8_t i = 0; i < 16; i++) {
            uint8_t l = leftShift(i + b_div, b_and, stretch);
            uint8_t r = rightShift(i + b_div + 1, 8 - b_and, stretch);
            offset[i] = l | r;
        }
    } else {
        for (uint8_t i = 0; i < 16; i++) {
            offset[i] = stretch[i + b_div];
        }
    }
    memset(sum, 0, 16);
    for (size_t i = 1; i <= c; i++) {
        double_func(tmp, L_dollar);
        double_trailings(tmp, __builtin_ctz(i));
        xor(offset, offset, tmp);
        xor(tmp, offset, C);
        lea_decrypt(tmp, tmp);
        xor(P, offset, tmp);
        xor(sum, P, sum);
        C += 16;
        P += 16;
    }
    xor(tmp, sum, offset);
    xor(tmp, tmp, L_dollar);
    lea_encrypt(tmp, tag);
    //hash without A = 0
    memset(tmp, 0, 16);
    xor(tag, tmp, tag);
    if (memcmp(C, tag, 16) != 0){
        return 0;
    } else
        return 1;
}
