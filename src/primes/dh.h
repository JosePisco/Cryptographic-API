#ifndef DH_H
#define DH_H

#include <openssl/bn.h>

int gen_dh_privkey(BIGNUM *privkey);

int gen_dh_modulus(BIGNUM *modulus, int nbits, BN_CTX *ctx);

#endif /* DH_H */