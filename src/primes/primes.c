#include <stdbool.h>

#include "../bpsw/baillie_psw.h"
#include "../prng/lfsr.h"
#include "primes.h"

int is_prime(BIGNUM *a, BN_CTX *ctx)
{
    return bn_is_prime_bpsw(a, ctx);
}

int get_prime(BIGNUM *r, int n, BN_CTX *ctx)
{
    BIGNUM *two, *rand;
    int ret = 0;

    BN_CTX_start(ctx);

    if ((two = BN_CTX_get(ctx)) == NULL)
		goto done;
	if ((rand = BN_CTX_get(ctx)) == NULL)
		goto done;

    if (!BN_set_word(two, 2))
        goto done;
    if (!BN_getrandom(rand, n))
        goto done;

    while (true) {
        if (!BN_is_odd(rand))
            if (!BN_add(rand, rand, BN_value_one()))
                goto done;

        if (is_prime(rand, ctx)) {
            ret = 1;
            break;
        }

        if (!BN_add(rand, rand, two))
            goto done;
    }

    BN_copy(r, rand);

    ret = 1;

    done:
        BN_CTX_end(ctx);

        return ret;
}

int get_safe_prime(BIGNUM *modulus, int nbits, BN_CTX *ctx)
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
