#include <stdbool.h>

#include "../bpsw/baillie_psw.h"
#include "../prng/lfsr.h"
#include "primes.h"

int is_prime(BIGNUM *a)
{
    if (BN_baillie_psw(a) == true)
        return 1;
    return 0;
}

int get_prime(BIGNUM *r, int n)
{
    int result = 0;

    BIGNUM *bn_two = BN_new();
    BIGNUM *rand = BN_new();

    BN_CTX *ctx = BN_CTX_new();

    if (!BN_set_word(bn_two, 2)) goto done;

    char *hexrand = hexrandom(n, 0);
    //printf("%s\n", hexrand);
    if (!BN_hex2bn(&rand, hexrand)) goto done;
    free(hexrand);


    while (true) {
        if (!BN_is_odd(rand))
            if (!BN_add(rand, rand, BN_value_one())) goto done;

        if (is_prime(rand)) {
            result = 1;
            break;
        }

        if (!BN_add(rand, rand, bn_two)) goto done;
    }

    BN_copy(r, rand);

    done:
        BN_free(rand);
        BN_free(bn_two);
        BN_CTX_free(ctx);
        return result;
}
