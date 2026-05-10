#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>

void print_hash(unsigned char hash[]) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <filename>\n", argv[0]);
        return 1;
    }

    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror("File opening failed");
        return 1;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    unsigned char buffer[1024];
    int bytesRead = 0;

    while ((bytesRead = fread(buffer, 1, 1024, file)) != 0) {
        SHA256_Update(&sha256, buffer, bytesRead);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    printf("SHA-256 Fingerprint: ");
    print_hash(hash);

    fclose(file);
    return 0;
}

