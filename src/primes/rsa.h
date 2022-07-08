#ifndef RSA_H
#define RSA_H

#include <openssl/bn.h>

typedef struct rsa_key {
    int bits;
    BIGNUM *p;
    BIGNUM *q;
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
    BIGNUM *phi;
} rsa_key;

rsa_key *gen_rsa_key(int nbits);

void free_rsa_key(rsa_key *key);

#endif /* RSA_H */