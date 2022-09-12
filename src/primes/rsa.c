#include "primes.h"
#include "rsa.h"

void free_rsa_key(rsa_key *key)
{
	BN_free(key->p);
	BN_free(key->q);
	BN_free(key->phi);
	BN_free(key->e);
	BN_free(key->d);
	BN_free(key->n);

	free(key);
}

int gen_rsa_key(struct rsa_key *key, int nbits, BN_CTX *ctx)
{
	BIGNUM *n, *p, *q, *p_minus_one, *e, *d, *phi, *tmp;
	int bitlength;
	int ret = 0;

	BN_CTX_start(ctx);

	if ((n = BN_CTX_get(ctx)) == NULL)
		goto done;
	if ((p = BN_CTX_get(ctx)) == NULL)
		goto done;
	if ((q = BN_CTX_get(ctx)) == NULL)
		goto done;
	if ((p_minus_one = BN_CTX_get(ctx)) == NULL)
		goto done;
	if ((e = BN_CTX_get(ctx)) == NULL)
		goto done;
	if ((d = BN_CTX_get(ctx)) == NULL)
		goto done;
	if ((phi = BN_CTX_get(ctx)) == NULL)
		goto done;
	if ((tmp = BN_CTX_get(ctx)) == NULL)
		goto done;

	if (!BN_set_word(e, 65537))
		goto done;

	while (1) {
		if (!get_prime(p, nbits / 2, ctx))
			goto done;
		if (!get_prime(q, nbits / 2 + 1, ctx))
			goto done;
		if (!BN_mul(n, p, q, ctx))
			goto done;

		bitlength = BN_num_bits(n);
		if (bitlength != nbits)
			continue;

		if (!BN_sub(p_minus_one, p, BN_value_one()))
			goto done;
		if (!BN_sub(tmp, q, BN_value_one()))
			goto done;
		if (!BN_mul(phi, p_minus_one, tmp, ctx))
			goto done;
		if (!BN_mod(tmp, phi, e, ctx))
			goto done;

		if (BN_is_zero(tmp))
			continue;

		break;
	}

	if (!BN_mod_inverse(d, e, phi, ctx))
		goto done;

	key->p = BN_dup(p);
	key->q = BN_dup(q);
	key->phi = BN_dup(phi);
	key->e = BN_dup(e);
	key->d = BN_dup(d);
	key->n = BN_dup(n);

	ret = 1;

 done:
	BN_CTX_end(ctx);

	return ret;
}

/* Sends signed message from p1 to p2 */
int rsa_pksign(BIGNUM *s, unsigned char *msg, rsa_key *key, BN_CTX *ctx)
{
	int ret = 0;

	BIGNUM *hash;
	BIGNUM *res;

	BN_CTX_start(ctx);

	if ((hash = BN_CTX_get(ctx)) == NULL)
		goto done;
	if ((res = BN_CTX_get(ctx)) == NULL)
		goto done;

	unsigned char *md = malloc(sizeof(unsigned char) * SHA256_DIGEST_LENGTH);

	SHA256(msg, 64, md); // RSA OR HMAC ??? LOL TAS LA REF ?
	if (!BN_bin2bn(md, SHA256_DIGEST_LENGTH, hash))
		goto done;
	free(md);

	/* s = H(m)^d mod n */
	if (!BN_mod_exp(s, hash, key->d, key->n, ctx))
		goto done;

	/* S = s^e mod n and the signature verifies */
	if (!BN_mod_exp(res, s, key->e, key->n, ctx))
		goto done;

	ret = 1;

 done:
	BN_CTX_end(ctx);

	return ret;
}
