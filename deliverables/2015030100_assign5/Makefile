all: logger acmonitor

logger: logger.c
	gcc -g -Wall -Wno-incompatible-pointer-types -fPIC -shared -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc -g -Wno-incompatible-pointer-types acmonitor.c -o acmonitor

clean:
	rm -rf logger.so
	rm -rf acmonitor
	rm -rf file_*