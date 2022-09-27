#ifndef GEN_PRIME_H
#define GEN_PRIME_H

#include <openssl/bn.h>

/* returns 1 or 0 if the number a is respectively prime or not
 * using the Baillie-PSW primality test
*/
int is_prime(BIGNUM *a, BN_CTX *ctx);

/* Requests entropy to generate a prime number */
int get_prime(BIGNUM *r, int n, BN_CTX *ctx);

/* Generates a prime of the form 2*q+1 ; with q prime */
int get_safe_prime(BIGNUM *modulus, int nbits, BN_CTX *ctx);


#endif /* GEN_PRIME_H */