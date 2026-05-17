#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/sha.h>

void get_sha256(char *path, char output[65]) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        strcpy(output, "0000000000000000000000000000000000000000000000000000000000000000");
        return;
    }

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

int main() {
    struct dirent *de;
    DIR *dr = opendir(".");
    struct stat st;
    char hash_out[65];

    if (dr == NULL) {
        perror("Unable to open directory");
        return 1;
    }

    printf("===========================================\n");
    printf("   AUTOMATED HOST VAULT AUDIT IN PROGRESS  \n");
    printf("===========================================\n");

    while ((de = readdir(dr)) != NULL) {
        // Skip directory links and self-generated audit logs/baselines to prevent infinite loops
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0 || 
            strcmp(de->d_name, "sentinel.log") == 0 || strcmp(de->d_name, ".baseline.txt") == 0) {
            continue;
        }

        if (stat(de->d_name, &st) == 0) {
            // S_ISREG checks if the item is a regular file rather than a directory or device link
            if (S_ISREG(st.st_mode)) {
                get_sha256(de->d_name, hash_out);
                printf("Artifact: %-20s | Size: %-6ld Bytes | SHA-256: %s\n", 
                       de->d_name, (long)st.st_size, hash_out);
            }
        }
    }

    closedir(dr);
    return 0;
}
