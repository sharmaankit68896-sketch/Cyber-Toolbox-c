#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <openssl/sha.h>

// Function to calculate SHA-256 hash
void calculate_sha256(char *path, char output[65]) {
    FILE *file = fopen(path, "rb");
    if (!file) return;

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buffer[1024];
    int bytesRead;

    while ((bytesRead = fread(buffer, 1, 1024, file)) != 0) {
        SHA256_Update(&sha256, buffer, bytesRead);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);
    fclose(file);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <target_file>\n", argv[0]);
        return 1;
    }

    char *target = argv[1];
    struct stat st;
    if (stat(target, &st) != 0) {
        perror("Stat failed");
        return 1;
    }

    char current_hash[65];
    calculate_sha256(target, current_hash);

    FILE *base = fopen(".baseline.txt", "r");

    if (!base) {
        // Mode 1: Create Baseline
        printf("[+] No baseline found. Creating new snapshot for %s...\n", target);
        base = fopen(".baseline.txt", "w");
        fprintf(base, "%ld %ld %s", (long)st.st_size, (long)st.st_mtime, current_hash);
        fclose(base);
        printf("[*] Baseline saved. Run again to audit.\n");
    } else {
        // Mode 2: Audit Mode
        long b_size, b_time;
        char b_hash[65];
        fscanf(base, "%ld %ld %s", &b_size, &b_time, b_hash);
        fclose(base);

        int tampered = 0;

        printf("--- [Sentinel Audit Report] ---\n");
        if (b_size != st.st_size) {
            printf("[!] ALERT: Size Mismatch! (Base: %ld, Current: %ld)\n", b_size, st.st_size);
            tampered = 1;
        }
        if (b_time != st.st_mtime) {
            printf("[!] ALERT: Modification Time Mismatch!\n");
            tampered = 1;
        }
        if (strcmp(b_hash, current_hash) != 0) {
            printf("[!] ALERT: SHA-256 Hash Mismatch! Content altered.\n");
            tampered = 1;
        }

        if (!tampered) {
            printf("[✓] Integrity Verified. No changes detected.\n");
        } else {
            printf("\n[DANGER] File integrity compromised.\n");
        }
    }

    return 0;
}
