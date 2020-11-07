CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic -Wno-unused-result
OBJFILES = main.o rsa.o utils.o
LIBS = -lm

TARGET = assign_3


all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CCFLAGS) $(DBUG) -o $(TARGET) $(OBJFILES) $(LIBS)

%.o: %.c
	$(CC) $(DBUG) $(CCFLAGS) -o $@ -c $<

clean:
	rm -f $(TARGET) *.o
