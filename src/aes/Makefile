CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -pedantic

CRYPTO_OBJS = aes.o
OBJS = main.o

#BIN = primes
all: $(CRYPTO_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $< -c

#all: $(CRYPTO_OBJS) $(OBJS)
#	$(CC) $^ -c $(BIN) $(CFLAGS) $(CRYPTO_FLAGS)

clean:
	$(RM) $(CRYPTO_OBJS) $(OBJS) *~

.PHONY: clean
