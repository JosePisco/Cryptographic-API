#ifndef RSA_H
#define RSA_H

#include <openssl/bn.h>

typedef struct rsa_key {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
    int bits;
} rsa_key;

int gen_rsa_key(struct rsa_key *key, int nbits, BN_CTX *ctx);

void free_rsa_key(rsa_key *key);

#endif /* RSA_H */