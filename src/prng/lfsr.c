#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "lfsr.h"

static uint64_t lfsr;
static const uint8_t taps[NB_TAPS] = {LFSR_LENGTH, 56, 13, 10};

static int randoms(uint64_t *randf, uint64_t min, uint64_t max)
{
    int retries = 10;
    unsigned long long rand64;

    while(retries--) {
        if (__builtin_ia32_rdrand64_step(&rand64)) {
            *randf = (float) rand64 / ULONG_MAX * (max - min) + min;
            return 1;
        }
    }

    return 0;
}

void init_lfsr()
{
    if (!randoms(&lfsr, 0, 9223372036854775807)) /* 2^63 - 1 */
        printf("Failed to get a random value\n");
}

static uint8_t lclock(void)
{
    uint64_t bit = ((lfsr >> (LFSR_LENGTH - taps[0])) ^ (lfsr >> (LFSR_LENGTH - taps[1]))
                    ^ (lfsr >> (LFSR_LENGTH - taps[2])) ^ (lfsr >> (LFSR_LENGTH - taps[3]))) & 1u;
    lfsr = (lfsr >> 1) | (bit << (LFSR_LENGTH - 1));
    return bit;
}

static void shuffle(void)
{
    for (uint64_t i = 0; i < SHUFFLE; ++i)
        lclock();
}

void stream(uint64_t randomness)
{

    /* Initial shuffle */
    shuffle();

    /* Randomness */
    for (uint64_t j = 0; j < randomness; ++j) {
        uint8_t bit = lclock();
        printf("%u", bit); /* output bit */
    }

    /* Final shuffle */
    shuffle();
}

static char get_hex_char(int value)
{
    if (value < 10)
        return 48 + value;
    return 55 + value;
}

void hexrandom(char *hexrand, int bits, uint64_t seed)
{
    int count, value;
    size_t index;

    if (seed)
        lfsr = seed;

    shuffle();

    count = 0;
    value = 0;
    index = 0;

    switch (bits % HEX_BIT_SIZE) {
        case 3:
            count = 2;
            value = 4;
            break;
        case 2:
            count = 1;
            value = 2;
            break;
        case 1:
            count = 0;
            value = 8;
            hexrand[index] = '1';
            index++;
            value = 1;
            break;
        default: /* has to be 0 */
            count = 3;
            value = 8;
            break;
    }

    for (int i = 1; i < bits; ++i) {
        uint8_t bit = lclock();
        if (bit == 1)
            value += (1 << (3 - count));

        if (count == 3) {
            hexrand[index] = get_hex_char(value);
            index++;
            count = 0;
            value = 0;
        }
        else
            count++;
    }

    shuffle();
}

/*
 * requests size bytes of random from entropy source and places it in bytes.
 * if a seed is specified (non zero), it will use it.
 */
int bytesrandom(unsigned char *bytes, int size, uint64_t seed)
{
    int ret = 0;

    if (seed)
        lfsr = seed;

    shuffle();

    int value;
    for (int i = 0; i < size; i++) {
        value = 0;
        for (int j = 0; j < 8; j++) {
            uint8_t bit = lclock();
            value += (bit * (1 << j));
        }

        bytes[i] = value;
    }

    bytes[size] = '\0';

    shuffle();

    ret = 1;

    return ret;
}

int BN_getrandom(BIGNUM *r, int n)
{
    int hexsize;
    int ret = 0;

    hexsize = n / HEX_BIT_SIZE;
    if (n % HEX_BIT_SIZE != 0)
        hexsize++;

    char *r_str = malloc(sizeof(char) * (hexsize + 1));
    hexrandom(r_str, n, NO_SEED);

    r_str[hexsize] = '\0';

    if (!BN_hex2bn(&r, r_str))
        goto done;

    ret = 1;

 done:
    free(r_str);

    return ret;
}
