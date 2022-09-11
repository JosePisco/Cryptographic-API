#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#include "lfsr.h"

#define HEX_BIT_SIZE 4

#define NB_TAPS 4
#define LFSR_LENGTH 64
#define SHUFFLE 2048
#define OUTPUT_GIVEN 1024

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

char *hexrandom(int randomness, uint64_t seed)
{
    if (seed)
        lfsr = seed;

    shuffle();

    int size = randomness / HEX_BIT_SIZE;
    if (randomness % HEX_BIT_SIZE != 0)
        size++;

    char *rand = malloc(sizeof(char) * (size + 1));
    int count = 0;
    int value = 0;
    size_t index = 0;

    if (randomness % HEX_BIT_SIZE == 0) { // 4
        count = 3;
        value = 8;
    }
    else if (randomness % HEX_BIT_SIZE == 3) { // 3
        count = 2;
        value = 4;
    }
    else if (randomness % HEX_BIT_SIZE == 2) { // 2
        count = 1;
        value = 2;
    }
    else { // 1
        count = 0;
        rand[index] = '1';
        index++;
        value = 1;
    }

    for (int i = 1; i < randomness; ++i) {
        uint8_t bit = lclock();
        if (bit == 1)
            value += (1 << (3 - count));

        if (count == 3) {
            rand[index] = get_hex_char(value);
            index++;
            count = 0;
            value = 0;
        }
        else
            count++;
    }

    shuffle();
    rand[size] = '\0';

    return rand;
}
