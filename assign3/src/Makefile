CC = gcc
DBUG = -g
# -O2 
CCFLAGS = -Wall -pedantic
OBJFILES = main.o rsa.o utils.o
LIBS = -lm

TARGET = assign_3


all: $(TARGET)

$(TARGET): $(OBJFILES)
	$(CC) $(CCFLAGS) $(DBUG) -o $(TARGET) $(OBJFILES) $(LIBS)

%.o: %.c
	$(CC) $(DBUG) -o $@ -c $<

clean:
	rm -f $(TARGET) *.o
