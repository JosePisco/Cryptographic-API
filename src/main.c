#include <openssl/bn.h>
#include <stdio.h>
#include <time.h>

#include "bpsw/baillie_psw.h"
#include "primes/primes.h"
#include "primes/rsa.h"
#include "primes/dh.h"
#include "prng/lfsr.h"

int main(void)
{
    // init lfsr
    init_lfsr();

    BIGNUM *prime = BN_new();

    printf("generating prime...");
    fflush(stdout);
    get_prime(prime, 1024);

    char *prime_str = BN_bn2dec(prime);
    printf(" found !\n %s\n", prime_str);

    rsa_key *key = gen_rsa_key(1024);

    char *p_ = BN_bn2dec(key->p);
    char *q_ = BN_bn2dec(key->q);
    char *e_ = BN_bn2dec(key->e);
    char *d_ = BN_bn2dec(key->d);
    char *n_ = BN_bn2dec(key->n);
    char *phi_ = BN_bn2dec(key->phi);
    printf("p = %s\n", p_);
    printf("q = %s\n", q_);
    printf("e = %s\n", e_);
    printf("d = %s\n", d_);
    printf("n = %s\n", n_);
    printf("phi = %s\n", phi_);
    free(p_);
    free(q_);
    free(e_);
    free(d_);
    free(n_);
    free(phi_);

    BIGNUM *dh_modulus = BN_new();
    gen_dh_modulus(dh_modulus, 1024);
    char *dh_str = BN_bn2dec(dh_modulus);
    printf("p = %s\n", dh_str);
    free(dh_str);

    BN_free(dh_modulus);

    free_rsa_key(key);
    free(prime_str);
    BN_free(prime);
    return 0;
}
