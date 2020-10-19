CC=gcc
CFLAGS=-g -funsigned-char

all: simple_crypto demo.c
	$(CC) $(CFLAGS) -o demo demo.c simple_crypto.o

simple_crypto: simple_crypto.c simple_crypto.h
	$(CC) $(CFLAGS) -c simple_crypto.c

clean:
	rm *.o demo