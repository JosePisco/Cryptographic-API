#include <openssl/bn.h>
#include <stdio.h>

#include "bpsw/baillie_psw.h"
#include "primes/primes.h"

int main(void)
{
    BIGNUM *prime = BN_new();

    printf("generating prime...");
    fflush(stdout);
    get_prime(prime, 2048);

    char *prime_str = BN_bn2dec(prime);
    printf(" found !\n %s\n", prime_str);

    free(prime_str);
    BN_free(prime);
    return 0;
}
