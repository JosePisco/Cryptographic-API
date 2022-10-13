/*
 * AES implementation inspired from kokke/tinyAES and adapted for
 * this application.
 */

#include "aes.h"
#include <string.h>

static const uint8_t sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16 };

static const uint8_t inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d };

/* Round constants */
static const uint8_t r_consts[] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39 };

/* xor() performs the xor operation on 16 bytes of blk and iv
 * and stores the result in out
 */
static void xor_blk(uint8_t *blk, uint8_t *iv, uint8_t *out)
{
    for (int i = 0; i < AES_BLOCKSIZE; i++) {
        out[i] = blk[i] ^ iv[i];
    }
}

/* Expands and returns a list of key matrices for the given master_key */
static void key_expansion(uint8_t *round_keys, const uint8_t *key)
{
    uint8_t i, j, k;
    uint8_t state_col_tmp[4];

    /* The first round key it the key itself */
    for (i = 0; i < NK; i++) {
        round_keys[(i * STATE_SIZE) + 0] = key[(i * STATE_SIZE) + 0];
        round_keys[(i * STATE_SIZE) + 1] = key[(i * STATE_SIZE) + 1];
        round_keys[(i * STATE_SIZE) + 2] = key[(i * STATE_SIZE) + 2];
        round_keys[(i * STATE_SIZE) + 3] = key[(i * STATE_SIZE) + 3];
    }

    /* All the other round keys depend on the previous one */
    for (i = NK; i < STATE_SIZE * (N_ROUNDS + 1); i++) {
        k = (i - 1) * STATE_SIZE;
        state_col_tmp[0] = round_keys[k + 0];
        state_col_tmp[1] = round_keys[k + 1];
        state_col_tmp[2] = round_keys[k + 2];
        state_col_tmp[3] = round_keys[k + 3];

        if (i % NK == 0)
        {
            const uint8_t u8tmp = state_col_tmp[0];
            state_col_tmp[0] = state_col_tmp[1];
            state_col_tmp[1] = state_col_tmp[2];
            state_col_tmp[2] = state_col_tmp[3];
            state_col_tmp[3] = u8tmp;

            state_col_tmp[0] = sbox[state_col_tmp[0]];
            state_col_tmp[1] = sbox[state_col_tmp[1]];
            state_col_tmp[2] = sbox[state_col_tmp[2]];
            state_col_tmp[3] = sbox[state_col_tmp[3]];

            state_col_tmp[0] = state_col_tmp[0] ^ r_consts[i / NK];
        }

        if (i % NK == 4)
        {
            state_col_tmp[0] = sbox[state_col_tmp[0]];
            state_col_tmp[1] = sbox[state_col_tmp[1]];
            state_col_tmp[2] = sbox[state_col_tmp[2]];
            state_col_tmp[3] = sbox[state_col_tmp[3]];
        }

        j = i * 4;
        k = (i - NK) * 4;
        round_keys[j + 0] = round_keys[k + 0] ^ state_col_tmp[0];
        round_keys[j + 1] = round_keys[k + 1] ^ state_col_tmp[1];
        round_keys[j + 2] = round_keys[k + 2] ^ state_col_tmp[2];
        round_keys[j + 3] = round_keys[k + 3] ^ state_col_tmp[3];
    }
}

/* The bytes of the round key are XOR'd with the bytes of the state */
static void add_round_key(state_t *state, uint8_t round, const uint8_t *round_keys)
{
    uint8_t i, j;

    for (i = 0; i < STATE_SIZE; i++) {
        for (j = 0; j < STATE_SIZE; j++) {
            (* state)[j][i] ^= round_keys[(round * STATE_SIZE * 4) + (j * STATE_SIZE) + i];
        }
    }
}

/* Each byte of the state is substituted for a different byte in the S-box. */
static void sub_bytes(state_t *state)
{
    uint8_t i, j;

    for (i = 0; i < STATE_SIZE; i++) {
        for (j = 0; j < STATE_SIZE; j++)
            (* state)[i][j] = sbox[(* state)[i][j]];
    }
}

/* Inverse of sub_bytes() method used for decryption */
static void inv_sub_bytes(state_t *state)
{
    uint8_t i, j;

    for (i = 0; i < STATE_SIZE; i++) {
        for (j = 0; j < STATE_SIZE; j++)
            (* state)[i][j] = inv_sbox[(* state)[i][j]];
    }
}

/* The last three rows of the state matrix are transposed */
static void shift_rows(state_t *state)
{
    uint8_t tmp;

    /* First row is not shifted */

    /* Second row is shifted one to the left */
    tmp = (* state)[0][1];
    (* state)[0][1] = (* state)[1][1];
    (* state)[1][1] = (* state)[2][1];
    (* state)[2][1] = (* state)[3][1];
    (* state)[3][1] = tmp;

    /* Third row is shifted two to the left */
    tmp = (* state)[0][2];
    (* state)[0][2] = (* state)[2][2];
    (* state)[2][2] = tmp;
    tmp = (* state)[1][2];
    (* state)[1][2] = (* state)[3][2];
    (* state)[3][2] = tmp;

    /* Fourth row is shifted three to the left */
    tmp = (* state)[0][3];
    (* state)[0][3] = (* state)[3][3];
    (* state)[3][3] = (* state)[2][3];
    (* state)[2][3] = (* state)[1][3];
    (* state)[1][3] = tmp;
}

/* Inverse of shift_rows() method used for decryption */
static void inv_shift_rows(state_t *state)
{
    uint8_t tmp;

    /* First row is not shifted */

    /* Second row is shifted one to the right */
    tmp = (* state)[3][1];
    (* state)[3][1] = (* state)[2][1];
    (* state)[2][1] = (* state)[1][1];
    (* state)[1][1] = (* state)[0][1];
    (* state)[0][1] = tmp;

    /* Third row is shifted two to the right */
    tmp = (* state)[0][2];
    (* state)[0][2] = (* state)[2][2];
    (* state)[2][2] = tmp;
    tmp = (* state)[1][2];
    (* state)[1][2] = (* state)[3][2];
    (* state)[3][2] = tmp;

    /* Fourth row is shifted three to the right */
    tmp = (* state)[3][3];
    (* state)[3][3] = (* state)[0][3];
    (* state)[0][3] = (* state)[1][3];
    (* state)[1][3] = (* state)[2][3];
    (* state)[2][3] = tmp;
}

/* See Section 4.1 in The Design of Rijndael */
static uint8_t xtime(uint8_t e)
{
    return e & 0x80 ? ((e << 1) ^ 0x1b) & 0xff : e << 1;
}

/*
 * Matrix multiplication is performed on the columns of the state, combining
 * the four bytes in each column. This is skipped in the final round.
 */
static void mix_columns(state_t *state)
{
    uint8_t i, t, u;

    for (i = 0; i < STATE_SIZE; i++) {
        t = (* state)[i][0] ^ (* state)[i][1] ^ (* state)[i][2] ^ (* state)[i][3];
        u = (* state)[i][0];
        (* state)[i][0] ^= t ^ xtime((* state)[i][0] ^ (* state)[i][1]);
        (* state)[i][1] ^= t ^ xtime((* state)[i][1] ^ (* state)[i][2]);
        (* state)[i][2] ^= t ^ xtime((* state)[i][2] ^ (* state)[i][3]);
        (* state)[i][3] ^= t ^ xtime((* state)[i][3] ^ u);
    }
}

/* Inverse of mix_columns() method used for decryption */
static void inv_mix_columns(state_t *state)
{
    uint8_t i, u, v;

    for (i = 0; i < STATE_SIZE; i++) {
        u = xtime(xtime((* state)[i][0] ^ (* state)[i][2]));
        v = xtime(xtime((* state)[i][1] ^ (* state)[i][3]));

        (* state)[i][0] ^= u;
        (* state)[i][1] ^= v;
        (* state)[i][2] ^= u;
        (* state)[i][3] ^= v;
    }

    mix_columns(state);
}

static void AES_encrypt(state_t *state, const uint8_t *round_keys)
{
    uint8_t i;

    add_round_key(state, 0, round_keys);

    for (i = 1; i < N_ROUNDS; i++) {
        /* Perform round */
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, i, round_keys);
    }

    /* Last round without mix_columns */
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, N_ROUNDS, round_keys);
}

static void AES_decrypt(state_t *state, const uint8_t *round_keys)
{
    uint8_t i;

    add_round_key(state, N_ROUNDS, round_keys);

    for (i = N_ROUNDS - 1; i > 0; i--) {
        /* Perform round */
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, i, round_keys);
        inv_mix_columns(state);
    }

    /* Last round withtout inv_mix_columns */
    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, 0, round_keys);
}

/* Init AES context for previously allocated aes_ctx and binds key to it */
void AES_CTX_init(AES_CTX *aes_ctx, const uint8_t *key)
{
    key_expansion(aes_ctx->round_keys, key);
}

/*
 * Binds initialisation vector iv of size AES_BLOCKSIZE
 * to aes_ctx AES context.
 */
void AES_CTX_set_IV(AES_CTX *aes_ctx, uint8_t *iv)
{
    memcpy(aes_ctx->iv, iv, AES_BLOCKSIZE);
}

/*
 * Encrypts padded plaintext of length multiple of 16
 * using AES-CBC mode of encryption. The result is stored in res of same size
 * as plaintext (multiple of 16)
 * It uses the key and IV in aes_ctx
 */
void AES_CBC_encrypt(AES_CTX *aes_ctx, uint8_t *plaintext, int length, uint8_t *res)
{
    /* Creates a copy of the IV to work with, to not alterate CTX IV */
    uint8_t iv[AES_BLOCKSIZE];
    memcpy(iv, aes_ctx->iv, AES_BLOCKSIZE);

    for (int i = 0; i < length; i += AES_BLOCKSIZE) {
        xor_blk(plaintext+i, iv, iv);
        AES_encrypt((state_t *) iv, aes_ctx->round_keys);

        /* write ciphertext to res */
        memcpy(res+i, iv, AES_BLOCKSIZE);
    }
}

/*
 * Decrypts ciphertext using AES-CBC mode of encryption.
 * The result is stored in res of same size as ciphertext (multiple of 16)
 * that is padded if original plaintext was padded
 * It uses the key and IV in aes_ctx
 */
void AES_CBC_decrypt(AES_CTX *aes_ctx, uint8_t *ciphertext, int length, uint8_t *res)
{
    /* Creates a copy of the IV to work with, to not alterate CTX IV */
    uint8_t ct[AES_BLOCKSIZE];
    uint8_t iv[AES_BLOCKSIZE];
    memcpy(iv, aes_ctx->iv, AES_BLOCKSIZE);

    for (int i = 0; i < length; i += AES_BLOCKSIZE) {
        memcpy(ct, ciphertext+i, AES_BLOCKSIZE);
        AES_decrypt((state_t *) ct, aes_ctx->round_keys);

        /* write plaintext to res */
        xor_blk(ct, iv, res+i);

        // get new block for decryption and assign new iv
        memcpy(iv, ciphertext+i, AES_BLOCKSIZE);
    }
}
