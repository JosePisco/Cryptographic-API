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

    char *hexrand = hexrandom(n, 0);
    if (hexrand == NULL)
        goto done;
    if (!BN_hex2bn(&rand, hexrand))
        goto done;
    free(hexrand);


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
