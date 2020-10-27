CC = gcc
DBUG = -g
CCFLAGS = -Wall -pedantic
# -O2
LIBSSL = -lssl -lcrypto

TARGETS = assign_2


all: $(TARGETS)

assign_2: assign_2.c
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(LIBSSL)

clean:
	rm -f $(TARGETS)
