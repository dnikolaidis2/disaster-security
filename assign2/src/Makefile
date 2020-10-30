CC = gcc
DBUG = -g
CCFLAGS = -Wall -O2 -pedantic -Wno-unused-result
LIBSSL = -lssl -lcrypto

TARGETS = assign_1


all: $(TARGETS)

assign_1: assign_1.c
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(LIBSSL)

clean:
	rm -f $(TARGETS)
