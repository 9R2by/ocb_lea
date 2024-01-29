#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "ocb/ocb.h"

#define MFENCE _mm_mfence();
#define LFENCE _mm_lfence();

#define ARR 1000000

void print_arr(uint8_t *arr, size_t size) {
    for (size_t i = 0; i < size; i++) printf("%u", arr[i]);
    printf("\n");
}

int cmp(const void *a, const void *b) {
    int aI = *(const int *) a;
    int bI = *(const int *) b;

    if (aI < bI) {
        return -1;
    } else if (aI > bI) {
        return 1;
    } else {
        return 0;
    }
}


int main(__attribute__((unused)) int argc, __attribute__((unused)) char *argv[]) {
    srand(time(NULL));
    size_t u = 0;
    int result = 0;
    uint32_t b_div = 0;
    uint32_t b_and = 0;
    uint32_t bottom = 0;
    size_t *encryption_cycles = calloc(ARR, sizeof(size_t));
    size_t *decryption_cycles = calloc(ARR, sizeof(size_t));
    uint8_t tmp[16];
    uint8_t L[16], L_dollar[16], sum[16], offset[16], ktop[16], nonce[16], tag[16];
    uint8_t stretch[24];
    while (u < ARR) {
        uint8_t *C = calloc(16 * 2, sizeof(uint8_t));
        uint8_t P_in[16] = {0};
        uint8_t P_out[16] = {0};
        for (uint8_t x = 0; x < 16; x++) {
            P_in[x] = rand() & 255;
        }

        memset(tmp, 0, 16);
        memset(nonce, 0, 16);

        uint64_t start, end;
        uint32_t ui;
        MFENCE
        start = __rdtscp(&ui);
        LFENCE

        lea_encrypt(tmp, L);
        double_func(L_dollar, L);
        memcpy(&nonce[4], nonce, 12);
        nonce[0] = 0;
        nonce[3] |= 1;
        bottom = nonce[15] & (uint8_t) (pow(2, 6) - 1);
        nonce[15] &= 192;
        lea_encrypt(nonce, ktop);
        memcpy(stretch, ktop, 16);
        memcpy(tmp, &ktop[1], 8);
        xor(tmp, tmp, ktop);
        memcpy(&stretch[16], tmp, 8);
        b_div = bottom / 8;
        b_and = bottom & 7;

        result = ocb_enc(C, P_in, 1, tmp,
                         L_dollar, stretch, offset,
                         sum, tag, b_and, b_div);

        MFENCE
        end = __rdtscp(&ui);
        LFENCE
        printf("OCB Encryption: %llu, %u\n", (end - start), result);
        encryption_cycles[u] = (end - start);

        memset(tmp, 0, 16);
        memset(nonce, 0, 16);
        memset(stretch, 0, 24);

        MFENCE
        start = __rdtscp(&ui);
        LFENCE

        lea_encrypt(tmp, L);
        double_func(L_dollar, L);
        memcpy(&nonce[4], nonce, 12);
        nonce[0] = 0;
        nonce[3] |= 1;
        bottom = nonce[15] & (uint8_t) (pow(2, 6) - 1);
        nonce[15] &= 192;
        lea_encrypt(nonce, ktop);
        memcpy(stretch, ktop, 16);
        memcpy(tmp, &ktop[1], 8);
        xor(tmp, tmp, ktop);
        memcpy(&stretch[16], tmp, 8);
        b_div = bottom / 8;
        b_and = bottom & 7;
        result = ocb_dec(P_out, C, 1, tmp, L_dollar,
                         stretch, offset, sum, tag, b_and, b_div);

        MFENCE
        end = __rdtscp(&ui);
        LFENCE
        printf("OCB Decryption: %llu, %u\n", (end - start), result);
        decryption_cycles[u] = (end - start);

        if (result && memcmp(P_out, P_in, 16) != 0) {
            printf("Compare input and output plaintext error");
            free(C);
            return 1;
        }
        free(C);
        u++;
    }

    qsort(encryption_cycles, ARR, sizeof(encryption_cycles[0]), cmp);
    printf("OCB Encryption Cycles Median: %llu\n", encryption_cycles[ARR / 2]);

    qsort(decryption_cycles, ARR, sizeof(decryption_cycles[0]), cmp);
    printf("OCB Decryption Cycles Median: %llu\n", decryption_cycles[ARR / 2]);

    free(encryption_cycles);
    free(decryption_cycles);

    return 0;
}
