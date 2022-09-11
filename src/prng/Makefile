CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -pedantic -mrdrnd

PRNG_OBJS = lfsr.o

#PRNG_BIN = lfsr

all: $(PRNG_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $< -c

#all: $(PRNG_OBJS)
#	$(CC) $^ -o $(PRNG_BIN) $(CFLAGS)

clean:
	$(RM) $(PRNG_OBJS) *~

.PHONY: clean
