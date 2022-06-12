#include <stdbool.h>
#include <time.h>

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
    //BIGNUM *bn_six = BN_new();
    //BIGNUM *k = BN_new();
    BIGNUM *rand = BN_new();
    //BIGNUM *rand_mod_six = BN_new();
    //BIGNUM *six_k = BN_new();
    //BIGNUM *six_k_one = BN_new();

    BN_CTX *ctx = BN_CTX_new();

    if (!BN_set_word(bn_two, 2)) goto done;
    //if (!BN_set_word(bn_six, 6)) goto done;

    char *hexrand = hexrandom(n, clock() * clock() - clock());
    if (!BN_hex2bn(&rand, hexrand)) goto done;
    free(hexrand);

    /*while (true) {
        if (!BN_mod(rand_mod_six, rand, bn_six, ctx)) goto done;
        if (BN_is_zero(rand_mod_six))
            break;
        if (!BN_add(rand, rand, BN_value_one())) goto done;
    }

    BN_copy(k, rand);

    while (true)
    {
        if (!BN_mul(six_k, k, bn_six, ctx)) goto done;
        if (!BN_add(six_k_one, six_k, BN_value_one())) goto done; // 6k + 1

        if (is_prime(six_k_one)) {
            result = 1;
            break;
        }

        if (!BN_sub(six_k_one, six_k, BN_value_one())) goto done; // 6k - 1

        if (is_prime(six_k_one)) {
            result = 1;
            break;
        }

        if (!BN_add(k, k, BN_value_one())) goto done; // k += 1
    }*/

    while (true) {
        if (!BN_is_odd(rand))
            if (!BN_add(rand, rand, BN_value_one())) goto done;

        if (is_prime(rand)) {
            result = 1;
            break;
        }

        if (!BN_add(rand, rand, bn_two)) goto done;
    }

    //BN_copy(r, six_k_one);
    BN_copy(r, rand);
    printf("size: %d\n", BN_num_bits(r));

    done:
        //BN_free(bn_six);
        //BN_free(k);
        BN_free(rand);
        BN_free(bn_two);
        //BN_free(rand_mod_six);
        //BN_free(six_k);
        //BN_free(six_k_one);
        BN_CTX_free(ctx);
        return result;
}
