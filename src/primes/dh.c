#include "dh.h"
#include "primes.h"
#include "../prng/lfsr.h"

#define DH_PRIVKEY_LEN 256 /* NIST recommandation*/

int gen_dh_privkey(BIGNUM *privkey)
{
    int ret = 0;
    char *privkey_str = hexrandom(DH_PRIVKEY_LEN, 0);
    if (!BN_hex2bn(&privkey, privkey_str))
        goto done;

    ret = 1;

    done:
        free(privkey_str);

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
