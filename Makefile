CC=gcc
CFLAGS=-Wall
LIBS=-lssl -lcrypto

all: scanner sentinel vault recursive_vault

scanner: fast_scanner.c
	$(CC) $(CFLAGS) fast_scanner.c -o scanner -lpthread

sentinel: Host-Security/sentinel.c
	$(CC) $(CFLAGS) Host-Security/sentinel.c -o sentinel $(LIBS)

vault: Host-Security/vault_audit.c
	$(CC) $(CFLAGS) Host-Security/vault_audit.c -o vault $(LIBS)

recursive_vault: Host-Security/recursive_vault.c
	$(CC) $(CFLAGS) Host-Security/recursive_vault.c -o recursive_vault $(LIBS)

clean:
	rm -f scanner sentinel vault recursive_vault
