#ifndef RSA_H
#define RSA_H

#include <openssl/bn.h>
#include <openssl/sha.h>

#define HEX_CHAR 4

typedef struct rsa_key {
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *phi;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
    const int bits;
} rsa_key;

int gen_rsa_key(struct rsa_key *key, int nbits, BN_CTX *ctx);
void free_rsa_key(rsa_key *key);

int rsa_pksign(BIGNUM *s, BIGNUM *hash, rsa_key *key, BN_CTX *ctx);
int rsa_pksign_dec(BIGNUM *hash, BIGNUM *s, rsa_key *key, BN_CTX *ctx);

#endif /* RSA_H */