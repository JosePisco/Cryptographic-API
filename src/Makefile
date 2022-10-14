CC = gcc
CFLAGS = -Wall -Wextra -Werror -std=c99 -pedantic
CDEBUG = -ggdb -fsanitize=address -fsanitize=undefined
LDFLAGS = -lcrypto -lasan

SUBDIRS = bpsw primes prng aes
SRC = $(wildcard */*.o) main.o
BIN = crypto

all: $(SUBDIRS)
	$(CC) -c $(CFLAGS) main.c
	$(CC) -o $(BIN) $(CFLAGS) $(SRC) $(LDFLAGS)

debug: $(SUBDIRS)
	$(CC) -c $(CFLAGS) main.c
	$(CC) -o $(BIN) $(CDEBUG) $(CFLAGS) $(SRC) $(LDFLAGS)
$(SUBDIRS):
	$(MAKE) -C $@

clean:
	for I in $(SUBDIRS);\
	do\
		$(MAKE) -C $$I $@ || exit 1;\
	done
	$(RM) $(BIN) *.o *.d *~

.PHONY: clean $(SUBDIRS)
