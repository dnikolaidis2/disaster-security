CC=gcc
CFLAGS=-std=c99 -g

all: crypto
	$(CC) $(CFLAGS) -o demo demo.c simple_crypto.o

crypto:
	$(CC) $(CFLAGS) -c simple_crypto.c