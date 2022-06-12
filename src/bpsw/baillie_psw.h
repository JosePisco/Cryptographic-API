#ifndef BAILLIE_PSW_H
#define BAILLIE_PSW_H

#define NUM_FIRST_PRIMES 669

#include <stdbool.h>
#include <openssl/bn.h>

/* PROTOTYPES */

/* The true 'test' part of the Lucas test */
bool BN_strong_lucas_test(BIGNUM *n, BIGNUM *D, BIGNUM *P);

/*
    Test N for primality using the strong Lucas test with Selfridge's
    parameters. Returns 1 if N is prime or a strong Lucas-Selfridge
    pseudoprime (in which case N is also a pseudoprime to the standard
    Lucas-Selfridge test). Returns 0 if N is definitely composite.

    The running time of the strong Lucas-Selfridge test is, on average,
    roughly 10 % greater than the running time for the standard
    Lucas-Selfridge test (3 to 7 times that of a single Miller's test).
    However, the frequency of strong Lucas pseudoprimes appears to be
    only (roughly) 30 % that of (standard) Lucas pseudoprimes, and only
    slightly greater than the frequency of base-2 strong pseudoprimes,
    indicating that the strong Lucas-Selfridge test is more computationally
    effective than the standard version.
*/
bool BN_strong_lucas_selfridge(BIGNUM *n);

/*
    Baillie-PSW algorithm. Combines a base 2 Miller-Rabin test altogether with
    a Strong Lucas pseudoprime test. It uses Selfridge references for the couple (P, Q)
*/
bool BN_baillie_psw(BIGNUM *n);


#endif /* BAILLIE_PSW_H */