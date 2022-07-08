#ifndef LFSR_H
#define LFSR_H

#include <stdint.h>

/* Used to first init the lfsr to some value */
void init_lfsr(void);

/* returns randomness bits of random from the prng in a memory allocated string */
char *hexrandom(int randomness, uint64_t seed);

#endif /* LFSR_H */