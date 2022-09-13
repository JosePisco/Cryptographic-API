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
    prime_size = 1024;
    printf("generating %d bits rsa key pair...", prime_size);
    fflush(stdout);

    rsa_key *key1 = malloc(sizeof(struct rsa_key));
    if (!gen_rsa_key(key1, prime_size, ctx))
        goto done;

    printf(" generated!\n");

    char *e_ = BN_bn2dec(key1->e);
    char *n_ = BN_bn2dec(key1->n);
    printf("e = %s\n", e_);
    printf("n = %s\n", n_);

    free(e_);
    free(n_);

    printf("---------------------------------------------------\n");
    printf("generating a second rsa key...");
    fflush(stdout);

    rsa_key *key2 = malloc(sizeof(struct rsa_key));
    if (!gen_rsa_key(key2, prime_size, ctx))
        goto done;

    printf(" generated!\n");

    printf("Alice(key1) wants to prove here identity to Bob (key2)\nsignatures...");
    fflush(stdout);

    unsigned char *m_md = malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH);
    if (m_md == NULL)
        goto done;
    unsigned char *m_dec_md = malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH);
    if (m_dec_md == NULL)
        goto done;

    BIGNUM *m, *m_dec, *c, *s, *hash, *hash_dec, *hash_dec_sign;
    if ((m = BN_CTX_get(ctx)) == NULL)
        goto done;
    if ((m_dec = BN_CTX_get(ctx)) == NULL)
        goto done;
    if ((c = BN_CTX_get(ctx)) == NULL)
        goto done;
    if ((s = BN_CTX_get(ctx)) == NULL)
        goto done;
    if ((hash = BN_CTX_get(ctx)) == NULL)
        goto done;
    if ((hash_dec = BN_CTX_get(ctx)) == NULL)
        goto done;
    if ((hash_dec_sign = BN_CTX_get(ctx)) == NULL)
        goto done;

    if (!BN_getrandom(m, 256))
        goto done;
    if (!BN_sha256(m_md, m))
        goto done;
    if (!BN_bin2bn(m_md, SHA256_DIGEST_LENGTH, hash))
        goto done;

    /* /!\ GOOD PRACTICES REQUIRE TWO DIFFERENT KEY PAIRS TO SIGN / ENCRYPT */
    /* Alice encrypts her message with Bob's public key and sends it to him */
    if (!rsa_encrypt(c, m, key2, ctx))
        goto done;
    /* Alice signs with her private key*/
    if (!rsa_pksign(s, hash, key1, ctx))
        goto done;

    /* Bob decrypts the message with his private key */
    if (!rsa_decrypt(m_dec, c, key2, ctx))
        goto done;
    /* Bob computes the hash of the decrypted message */
    if (!BN_sha256(m_dec_md, m_dec))
        goto done;
    /* Bob received and "decrypts" using Alice's public key */
    if (!rsa_pksign_dec(hash_dec_sign, s, key1, ctx))
        goto done;
    /*------------------------------------------------------ */

    if (!BN_bin2bn(m_dec_md, SHA256_DIGEST_LENGTH, hash_dec))
        goto done;

    printf(" signed !\n");
    printf("original hash                           : ");
    BN_print_fp(stdout, hash);
    printf("\n");
    printf("hash decrypted after signing            : ");
    BN_print_fp(stdout, hash_dec_sign);
    printf("\n");
    printf("messgaed hashed after decrypting message: ");
    BN_print_fp(stdout, hash_dec);
    printf("\n");

    free(m_md);
    free(m_dec_md);
    free_rsa_key(key1);
    free_rsa_key(key2);

    /*printf("---------------------------------------------------\n");
    printf("generating DH modulus...");
    fflush(stdout);

    BIGNUM *dh_modulus;
    prime_size = 3072;
    if ((dh_modulus = BN_CTX_get(ctx)) == NULL)
        goto done;
    gen_dh_modulus(dh_modulus, prime_size, ctx);
    char *dh_str = BN_bn2dec(dh_modulus);
    printf(" generated !\np = %s\n", dh_str);
    free(dh_str);*/

 done:
    BN_CTX_free(ctx);

    return 0;
}
