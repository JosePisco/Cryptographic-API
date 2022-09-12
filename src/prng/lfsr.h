#ifndef LFSR_H
#define LFSR_H

#include <stdint.h>

/* Used to first init the lfsr to some value */
void init_lfsr();

/* returns randomness bits of random from the prng in a memory allocated string */
char *hexrandom(int randomness, uint64_t seed);

int bytesrandom(unsigned char *bytes, int size, uint64_t seed);

#endif /* LFSR_H */