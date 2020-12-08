CC = gcc
DBUG = -g
# -O2 
CCFLAGS = -Wall -pedantic -Wno-unused-result
LIBS = -lpcap

all: monitor

monitor: monitor.c
	$(CC) $(CCFLAGS) $(DBUG) -o monitor monitor.c $(LIBS)

clean:
	rm -f monitor
