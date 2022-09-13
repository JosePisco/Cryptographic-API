#ifndef LFSR_H
#define LFSR_H

#include <openssl/bn.h>
#include <stdint.h>

#define HEX_BIT_SIZE 4

#define NO_SEED 0
#define NB_TAPS 4
#define LFSR_LENGTH 64
#define SHUFFLE 2048

/* Used to first init the lfsr to some value */
void init_lfsr();

/* Returns randomness bits of random from the prng in a memory allocated string */
char *hexrandom(int randomness, uint64_t seed);

/* Requests size bytes to the entropy source. seed if specified */
int bytesrandom(unsigned char *bytes, int size, uint64_t seed);

/* Generates a random bignum r of n bits */
int BN_getrandom(BIGNUM *r, int n);

#endif /* LFSR_H */