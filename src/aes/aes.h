#ifndef AES_H
#define AES_H

#include <stdint.h>

/* Block length in bytes - Never changes */
#define AES_BLOCKSIZE 16
#define AES_KEYEXP_SIZE 176
#define STATE_SIZE 4

/* FIPS - 197 Fig. 4 : number of 32 bits words in the key */
#define NK 8
#define N_ROUNDS 14

/* Defines the state of AES during encryption / decryption */
typedef uint8_t state_t[4][4];

/* Context of an AES object for encryption / decryption */
typedef struct AES_CTX {
    uint8_t iv[AES_BLOCKSIZE];
    uint8_t round_keys[AES_KEYEXP_SIZE];
} AES_CTX;

void AES_CTX_init(AES_CTX *aes_ctx, const uint8_t *key);
void AES_CTX_set_IV(AES_CTX *aes_ctx, uint8_t *iv);

void AES_CBC_encrypt(AES_CTX *aes_ctx, uint8_t *plaintext, int length, uint8_t *res);
void AES_CBC_decrypt(AES_CTX *aes_ctx, uint8_t *ciphertext, int length, uint8_t *res);

#endif /* AES_H */