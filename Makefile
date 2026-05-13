CC=gcc
CFLAGS=-Wall
LIBS=-lssl -lcrypto

all: scanner sentinel

scanner: fast_scanner.c
	$(CC) $(CFLAGS) fast_scanner.c -o scanner -lpthread

sentinel: Host-Security/sentinel.c
	$(CC) $(CFLAGS) Host-Security/sentinel.c -o sentinel $(LIBS)

clean:
	rm -f scanner sentinel
