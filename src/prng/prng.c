#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>

int cycle(uint32_t n, uint32_t seed);

int main(int argc, char *argv[])
{
  if (argc != 3)
    {
      printf("Usage: ./prng [seed] [cyle_size]\n");
      return 0;
    }

  uint32_t seed = atol(argv[1]);
  uint32_t n = seed;
  for (int i = 0; i < atol(argv[2]); ++i)
    {
      n ^= (n << 3) | (n >> 5);
    }
  printf("n:%u\n", n);
  cycle(n, seed);
  return 0;
}

int cycle(uint32_t n, uint32_t seed)
{
  uint32_t k = 0;
  uint32_t witness = n;
  n = seed;
  printf("TEMOIN: %u\n", witness);
  do
    {
      n ^= (n << 3) | (n >> 5);
      k++;
    }
  while (n != witness);
  
  printf("Cycle de %u\n", k);
  return 0;
}
