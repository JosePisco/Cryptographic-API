#ifndef DH_H
#define DH_H

#include <openssl/bn.h>

#define DH_PRIVKEY_LEN 256 /* NIST recommandation*/

int gen_dh_privkey(BIGNUM *privkey);

#endif /* DH_H */