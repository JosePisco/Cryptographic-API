#include "primes.h"

int main(void)
{
    BIGNUM *prime = BN_new();
    if (!get_prime(prime, 256)) goto done;

    done:
        BN_free(prime);
        return 0;
}
