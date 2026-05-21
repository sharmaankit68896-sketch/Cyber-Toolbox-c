CC=gcc
CFLAGS=-Wall
LIBS=-lssl -lcrypto

all: scanner sentinel_prime

scanner: Network-Security/fast_scanner.c
	$(CC) $(CFLAGS) Network-Security/fast_scanner.c -o scanner -lpthread

sentinel_prime: Host-Security/sentinel_prime.c
	$(CC) $(CFLAGS) Host-Security/sentinel_prime.c -o sentinel_prime $(LIBS)

clean:
	rm -f scanner sentinel_prime
