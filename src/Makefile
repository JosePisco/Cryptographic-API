CC = gcc
CFLAGS = -g3 -fsanitize=address -Wall -Wextra -Werror -std=c99 -pedantic
LDFLAGS = -lcrypto -lasan

SUBDIRS = bpsw primes prng
SRC = $(wildcard */*.o) main.o
BIN = crypto

all: $(SUBDIRS)
	$(CC) -c $(CFLAGS) main.c
	$(CC) -o $(BIN) $(CFLAGS) $(SRC) $(LDFLAGS)

$(SUBDIRS):
	$(MAKE) -C $@

clean:
	for I in $(SUBDIRS);\
	do\
		$(MAKE) -C $$I $@ || exit 1;\
	done
	$(RM) $(BIN) *.o *.d *~

.PHONY: clean $(SUBDIRS)
