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

    BIGNUM *bn_two = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *q_times_two = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    if (!BN_set_word(bn_two, 2)) goto done;

    while (1) {
        get_prime(q, nbits - 1);
        if (!BN_mul(q_times_two, q, bn_two, ctx)) goto done;
        if (!BN_add(modulus, q_times_two, BN_value_one())) goto done;
        if (is_prime(modulus))
            break;
    }

    if (BN_num_bits(modulus) != nbits)
        printf("PAS BON MODULUS\n");

    result = 1;

    done:
        BN_free(bn_two);
        BN_free(q);
        BN_free(q_times_two);
        BN_CTX_free(ctx);
        return result;
}
