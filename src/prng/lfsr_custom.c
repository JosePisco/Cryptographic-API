/*  RANDOM NUMBER GENERATOR using a LFSR.
    This is not cryptographically secure, avoid using it for such purposes

    The size of the LFSR corresponds the seed size in bits.
    Change the LFSR_LENGTH to change its size.
*/

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define NB_TAPS 4
#define LFSR_LENGTH 96
#define INITIAL_SHUFFLE 2048

static unsigned lfsr[LFSR_LENGTH];
static size_t taps[NB_TAPS] = {LFSR_LENGTH - 1, 76, 12, 9};
static size_t dtaps[NB_TAPS] = {77, 13, 10, 0}; // taps to decrypt - inverse of Berlekamp-Massey output

void unshift_lfsr(void)
{
    for (size_t i = 1; i < LFSR_LENGTH; ++i)
        lfsr[i - 1] = lfsr[i];
}

void unclock(void)
{
    char c = 0;
    for (size_t i = 0; i < NB_TAPS; ++i) {
        c ^= lfsr[dtaps[i]];
    }
    unshift_lfsr();
    lfsr[LFSR_LENGTH - 1] = c;
}

void unstream(size_t rounds)
{
    for (size_t i = 0; i < rounds; ++i)
        unclock();
}

static void dump_lfsr()
{
    printf("---LFSR---\n");
    for (size_t k = 0; k < LFSR_LENGTH; ++k)
        printf("%u", lfsr[k]);
    printf("\n----------\n");
}

void add_seed(char c, size_t i)
{
    // charge chaque char du message / seed dans le lfsr
    // can and should be changed to a seed typed in unsigned long ?
    lfsr[i+7] = (c & 1) == 1 ? 1 : 0;
    lfsr[i+6] = (c & 2) == 2 ? 1 : 0;
    lfsr[i+5] = (c & 4) == 4 ? 1 : 0;
    lfsr[i+4] = (c & 8) == 8 ? 1 : 0;
    lfsr[i+3] = (c & 16) == 16 ? 1 : 0;
    lfsr[i+2] = (c & 32) == 32 ? 1 : 0;
    lfsr[i+1] = (c & 64) == 64 ? 1 : 0;
    lfsr[i] = (c & 128) == 128 ? 1 : 0;
}

void shift_lfsr(void)
{
    for (size_t i = LFSR_LENGTH - 1; i > 0; --i)
        lfsr[i] = lfsr[i - 1];
}

char clock(void)
{
    char c = 0;
    for (size_t i = 0; i < NB_TAPS; ++i) {
        c ^= lfsr[taps[i]];
    }
    shift_lfsr();
    lfsr[0] = c;
    return c;
}

void stream(size_t rounds, int generate_random)
{
    for (size_t i = 0; i < rounds; ++i) {
        char c = clock();
        // prints output which is random if asked
        if (generate_random)
            printf("%d", c);
    }

    if (generate_random)
        printf("\n");
}

void init(char *seed)
{
    size_t seed_len = strlen(seed);
    for (size_t i = 0; i < seed_len; ++i)
        add_seed(seed[i], i * 8);
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        printf("Usage: ./lfsr [seed (string)] [random needed (long)]\n");
        return 1;
    }

    char *seed = argv[1];
    size_t seed_len = strlen(seed);

    if (seed_len * 8 != LFSR_LENGTH) {
        printf("ERROR: wrong seed len: should be %d and got %ld\n", LFSR_LENGTH / 8, seed_len);
        return 1;
    }

    unsigned long random_needed = atol(argv[2]);
    init(seed);

    /* original */
    dump_lfsr();

    /* Initial shuffle to not get the bits in the seed when wanting randomness */
    stream(INITIAL_SHUFFLE, 0);
    
    /* Asking for randomness: comes from the clock() function */
    printf("random bits: ");
    stream(random_needed, 1);

    /* shifted */
    dump_lfsr();

    /* sanity check */
    unstream(INITIAL_SHUFFLE + random_needed);

    /* should be back to original */
    dump_lfsr();

    return 1;
}
