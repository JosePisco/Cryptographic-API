#ifndef DH_H
#define DH_H

#include <openssl/bn.h>

int gen_dh_privkey(BIGNUM *privkey, int nbits);

int gen_dh_modulus(BIGNUM *modulus, int nbits);

#endif /* DH_H */