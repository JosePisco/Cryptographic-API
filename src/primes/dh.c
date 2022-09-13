#include "dh.h"
#include "primes.h"
#include "../prng/lfsr.h"

int gen_dh_privkey(BIGNUM *privkey)
{
    int ret = 0;

    if (!BN_getrandom(privkey, DH_PRIVKEY_LEN))
        goto done;

    ret = 1;

 done:
    return ret;
}

int gen_dh_modulus(BIGNUM *modulus, int nbits, BN_CTX *ctx)
{
    int ret = 0;

    while (1) {
        if (!get_prime(modulus, nbits - 1, ctx))
            goto done;
        if (!BN_mul_word(modulus, 2))
            goto done;
        if (!BN_add_word(modulus, 1))
            goto done;
        if (is_prime(modulus, ctx))
            break;
    }

    ret = 1;

 done:
    return ret;
}
