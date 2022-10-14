#include "dh.h"
#include "primes.h"
#include "../prng/lfsr.h"

/* Generates a Diffie-Hellman private key of size 256 bits */
int gen_dh_privkey(BIGNUM *privkey)
{
    int ret = 0;

    if (!BN_getrandom(privkey, DH_PRIVKEY_LEN))
        goto done;

    ret = 1;

 done:
    return ret;
}
