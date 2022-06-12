#ifndef GEN_PRIME_H
#define GEN_PRIME_H

#include <openssl/bn.h>

/*
    returns 1 or 0 if the number a is respectively prime or not
    using the Baillie-PSW primality test
*/
int is_prime(BIGNUM *a);

/*
    Every prime number is of the form 6k + 1 or 6k - 1
    We generate a random number of n bits and use it as our k
    that we will increment by one and check for every postulate if
    we obtain a prime number or not
    The of n bits prime will be stored in r, previously allocated.
*/
int get_prime(BIGNUM *r, int n);

#endif /* GEN_PRIME_H */