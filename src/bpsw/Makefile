CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -pedantic

CRYPTO_OBJS = crypto_utils.o miller_rabin.o baillie_psw.o tests_bpsw.o
OBJS = main.o

#BIN = baillie_psw

all: $(CRYPTO_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) $< -c

#all: $(CRYPTO_OBJS) $(OBJS)
#	$(CC) $^ -c $(BIN) $(CFLAGS) $(CRYPTO_FLAGS)


clean:
	$(RM) $(CRYPTO_OBJS) $(OBJS) *~

.PHONY: clean
