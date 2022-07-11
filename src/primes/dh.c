#include "dh.h"
#include "primes.h"
#include "../prng/lfsr.h"

int gen_dh_privkey(BIGNUM *privkey, int nbits)
{
    int result = 0;
    char *privkey_str = hexrandom(nbits, 0);
    if (!BN_hex2bn(&privkey, privkey_str)) goto done;

    result = 1;

    done:
        free(privkey_str);
        return result;
}

int gen_dh_modulus(BIGNUM *modulus, int nbits)
{
    int result = 0;

    while (1) {
        get_prime(modulus, nbits - 1);
        if (!BN_mul_word(modulus, 2)) goto done;
        if (!BN_add_word(modulus, 1)) goto done;
        if (is_prime(modulus))
            break;
    }

    result = 1;

    done:
        return result;
}
