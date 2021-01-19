
all: shellcode
shellcode: shellcode.c
	gcc -ansi -static -fno-stack-protector -z execstack -g -no-pie -m32 shellcode.c -o shellcode
clean:
	rm -f shellcode
