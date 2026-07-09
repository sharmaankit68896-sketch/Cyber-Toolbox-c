CC=gcc
CFLAGS=-Wall
LIBS=-lssl -lcrypto

all: scanner sentinel_prime packet_spy banner_grabber

scanner: Network-Security/fast_scanner.c
	$(CC) $(CFLAGS) Network-Security/fast_scanner.c -o scanner -lpthread

sentinel_prime: Host-Security/sentinel_prime.c
	$(CC) $(CFLAGS) Host-Security/sentinel_prime.c -o sentinel_prime $(LIBS)

packet_spy: Network-Security/packet_spy.c
	$(CC) $(CFLAGS) Network-Security/packet_spy.c -o packet_spy

banner_grabber: Network-Security/banner_grabber.c
	$(CC) $(CFLAGS) Network-Security/banner_grabber.c -o banner_grabber

clean:
	rm -f scanner sentinel_prime packet_spy banner_grabber
