#include "primes.h"
#include "rsa.h"

void free_rsa_key(rsa_key *key)
{
    BN_free(key->p);
    BN_free(key->q);
    BN_free(key->e);
    BN_free(key->d);
    BN_free(key->n);
    BN_free(key->phi);

    free(key);
}

struct rsa_key *gen_rsa_key(int nbits)
{
    rsa_key *key = malloc(sizeof(struct rsa_key));

    BIGNUM *p = BN_new();
    BIGNUM *p_minus_one = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *q_minus_one = BN_new();
    BIGNUM *e = BN_new();
    BIGNUM *d = BN_new();
    BIGNUM *n = BN_new();
    BIGNUM *phi = BN_new();
    BIGNUM *phi_mod_e = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    if (!BN_set_word(e, 65537)) goto done;

    while (1)
    {

        if (!get_prime(p, nbits/2)) goto done;
        if (!get_prime(q, nbits/2 + 1)) goto done; //
        if (!BN_mul(n, p, q, ctx)) goto done;

        int bitlength = BN_num_bits(n);
        if (bitlength != nbits)
            continue;

        if (!BN_sub(p_minus_one, p, BN_value_one())) goto done;
        if (!BN_sub(q_minus_one, q, BN_value_one())) goto done;
        if (!BN_mul(phi, p_minus_one, q_minus_one, ctx)) goto done;
        if (!BN_mod(phi_mod_e, phi, e, ctx)) goto done;

        if (BN_is_zero(phi_mod_e))
            continue;
        break;
    }

    if (!BN_mod_inverse(d, e, phi, ctx)) goto done;

    key->p = p;
    key->q = q;
    key->e = e;
    key->d = d;
    key->n = n;
    key->phi = phi;

    done:
        BN_free(p_minus_one);
        BN_free(q_minus_one);
        BN_free(phi_mod_e);
        BN_CTX_free(ctx);
        return key;
}
