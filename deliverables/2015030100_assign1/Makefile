CC=gcc
CFLAGS=-std=c99 -g

all: simple_crypto
	$(CC) $(CFLAGS) -o demo demo.c simple_crypto.o

simple_crypto:
	$(CC) $(CFLAGS) -c simple_crypto.c

clean:
	rm *.o demo