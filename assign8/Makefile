
all: Greeter shellcode
Greeter: Greeter.c
	gcc -ansi -static -fno-stack-protector -z execstack -g -no-pie -m32 Greeter.c -o Greeter
shellcode: shellcode.c
	gcc -ansi -static -fno-stack-protector -z execstack -g -no-pie -m32 shellcode.c -o shellcode
clean:
	rm -f Greeter shellcode
