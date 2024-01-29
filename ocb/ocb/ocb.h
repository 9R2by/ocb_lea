#ifndef OCB_OCB_H
#define OCB_OCB_H

#include <string.h>
#include <stdint.h>
#include <math.h>

#include "../lea/lea.h"

void xor(uint8_t arr_out[16], const uint8_t arr_1[16], const uint8_t arr_2[16]);

void double_func(uint8_t arr_out[16], const uint8_t arr_in[16]);

int ocb_enc(uint8_t *C, uint8_t *P, size_t p, uint8_t *tmp,
             uint8_t *L_dollar, uint8_t *stretch, uint8_t *offset,
             uint8_t *sum, uint8_t *tag, uint32_t b_and, uint32_t b_div);


int ocb_dec(uint8_t *P, uint8_t *C, size_t c,
            uint8_t *tmp, uint8_t *L_dollar,
            uint8_t *stretch, uint8_t *offset, uint8_t *sum, uint8_t *tag, uint32_t b_and, uint32_t b_div);


#endif //OCB_OCB_H
