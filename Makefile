CC=gcc
CFLAGS=-Wall
LIBS=-lssl -lcrypto

all: scanner sentinel vault recursive_vault

scanner: fast_scanner.c
	$(CC) $(CFLAGS) fast_scanner.c -o scanner -lpthread

sentinel: Host-security/sentinel.c
	$(CC) $(CFLAGS) Host-security/sentinel.c -o sentinel $(LIBS)

vault: Host-security/vault_audit.c
	$(CC) $(CFLAGS) Host-security/vault_audit.c -o vault $(LIBS)

recursive_vault: Host-security/recursive_vault.c
	$(CC) $(CFLAGS) Host-security/recursive_vault.c -o recursive_vault $(LIBS)

clean:
	rm -f scanner sentinel vault recursive_vault
