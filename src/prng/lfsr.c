#include <stdio.h>
#include <stdlib.h>

#include "lfsr.h"

#define HEX_BIT_SIZE 4

#define NB_TAPS 4
#define LFSR_LENGTH 64
#define SHUFFLE 2048
#define OUTPUT_GIVEN 1024

static uint64_t lfsr;
static uint8_t taps[NB_TAPS] = {LFSR_LENGTH, 56, 13, 10};

static uint8_t clock(void)
{
    uint64_t bit = ((lfsr >> (LFSR_LENGTH - taps[0])) ^ (lfsr >> (LFSR_LENGTH - taps[1]))
                    ^ (lfsr >> (LFSR_LENGTH - taps[2])) ^ (lfsr >> (LFSR_LENGTH - taps[3]))) & 1u;
    lfsr = (lfsr >> 1) | (bit << (LFSR_LENGTH - 1));
    return bit;
}

void shuffle(void)
{
    for (uint64_t i = 0; i < SHUFFLE; ++i)
        clock();
}

void stream(uint64_t randomness)
{

    /* Initial shuffle */
    shuffle();

    /* Randomness */
    for (uint64_t j = 0; j < randomness; ++j){
        uint8_t bit = clock();
        printf("%u", bit); //output bit
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

static int pow2(int n)
{
    int res = 1;
    for (int i = 0; i < n; ++i)
        res *= 2;
    return res;
}

char *hexrandom(int randomness, uint64_t seed)
{
    if (seed)
        lfsr = seed;

    shuffle();

    int size = randomness / HEX_BIT_SIZE;
    if (randomness % HEX_BIT_SIZE != 0)
        size++;

    char *rand = malloc(size);
    /*int count = (HEX_BIT_SIZE - 1 - (randomness % HEX_BIT_SIZE)) % HEX_BIT_SIZE; // bits manquants pour faire un char hexa
    // todo count
    printf("count : %d\n", count);

    size_t index = 0;
    int value = pow2(3 - count + 1); // start with first bit as 1 to avoid getting zeros and not matching bits asked*/
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
        uint8_t bit = clock();
        if (i == 0)
            printf("primier bit %u\n", bit);
        if (bit == 1)
            value += pow2(3 - count);

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
    //printf("strng: %s\n", rand);
    return rand;
}

/*int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("Usage: ./lfsr <seed[64]> <randomness>\n");
        return 1;
    }

    uint64_t seed = atol(argv[1]);
    uint64_t randomness = atol(argv[2]);

    stream(seed, randomness);
    char *toto = hexrandom(255);
    printf("value: %s\n", toto);
    free(toto);
    stream(0);

    return 0;
}
*/