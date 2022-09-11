#include <openssl/bn.h>
#include <stdio.h>

#include "bpsw/baillie_psw.h"
#include "primes/primes.h"
#include "primes/rsa.h"
#include "primes/dh.h"
#include "prng/lfsr.h"

int main(void)
{
    BIGNUM *prime;
    BN_CTX *ctx;
    int prime_size = 2048;

    if ((ctx = BN_CTX_new()) == NULL)
        goto done;
    if ((prime = BN_CTX_get(ctx)) == NULL)
        goto done;

    /* init lfsr value */
    init_lfsr();

    printf("generating prime of size %d...", prime_size);
    fflush(stdout);
    if (!get_prime(prime, prime_size, ctx))
        goto done;

    char *prime_str = BN_bn2dec(prime);
    printf(" found !\n %s\n", prime_str);

    free(prime_str);

    printf("---------------------------------------------------\n");
    printf("generating %d bits rsa key pair...", prime_size);
    fflush(stdout);

    prime_size = 1024;
    rsa_key *key = malloc(sizeof(struct rsa_key));
    if (!gen_rsa_key(key, prime_size, ctx))
        goto done;

    printf(" generated !\n");

    char *e_ = BN_bn2dec(key->e);
    char *n_ = BN_bn2dec(key->n);
    printf("e = %s\n", e_);
    printf("n = %s\n", n_);
    free(e_);
    free(n_);
    free_rsa_key(key);

    /*printf("---------------------------------------------------\n");
    printf("generating DH modulus...");
    fflush(stdout);

    BIGNUM *dh_modulus;
    if ((dh_modulus = BN_CTX_get(ctx)) == NULL)
        goto done;
    gen_dh_modulus(dh_modulus, 512, ctx);
    char *dh_str = BN_bn2dec(dh_modulus);
    printf(" generated !\np = %s\n", dh_str);
    free(dh_str);*/

 done:
    BN_CTX_free(ctx);

    return 0;
}
