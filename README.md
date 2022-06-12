# Cryptographic API

This repository provides a crypto API in C using Openssl BIGNUMS library.

## Random generator

### PRNG
A first approach to randomness is done by a simple 64-bits LFSR in `/src/prng`.
Every state of the LFSR is changed by calling the `clock()` method.
The `stream()` method, proceeds to shuffle a first time, then clocks for the number of random bits asked and shuffles another time.
`hexrandom()` has the same behavior as `stream()` but outputs an hexadecimal string  representing a big integer.

Beware that the LFSR can be reversed easily ! It is not cryptograpically secure. Its only purpose is to quickly provide psuedo-random to test and develop other parts of this API.


### CSPRNG
Is to be done.

## Primality testing

### Baillie-PSW primality test
To find primes, we need to test if the given number is prime. To do so, we use the **Baillie-PSW** primality test in `/src/bpsw`, adapted to bignums and cryptography. I develop more concerning the algorithm and details in my repository of the same name (https://github.com/JosePisco/Baillie-PSW).

## Key generation

### Prime generation
The generation of prime numbers is done by requesting random from the generator and iterating on every odd numbers and check for primality. Most code concerning primes is in `/src/primes`

### RSA
Is to be done.

### Diffie-Hellman
Is to be done.

# Work to do

## Random generator
- Implementing a CSPRNG for a better random generation.
- Diversify the type of output when requesting for randomness towards the PRNG (and thus, for the CSPRNG).

## Key generation

- Code for key generation for RSA / Diffie-Hellman to start with.
- Key derivation

## Others

- Implement other protocols and signatures: DSA, ECC, ECDSA, El-Gamal...
- Rebuild the architecture to shape it like a real API
