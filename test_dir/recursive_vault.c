#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/sha.h>

void calculate_file_sha256(char *path, char output[65]) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        strcpy(output, "ERROR_OPENING_FILE_FOR_HASHING_ROUTINE_FAILURE");
        return;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buffer[4096]; // Increased chunk size to 4KB for optimal filesystem performance
    int bytesRead;

    while ((bytesRead = fread(buffer, 1, sizeof(buffer), file)) != 0) {
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

void traverse_and_audit(const char *base_path) {
    struct dirent *de;
    DIR *dr = opendir(base_path);
    struct stat st;
    char path_buffer[1024];
    char hash_out[65];

    if (dr == NULL) return; // Silent return for inaccessible system folders

    while ((de = readdir(dr)) != NULL) {
        // Strict baseline system link filtering
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0 || 
            strcmp(de->d_name, ".git") == 0 || strcmp(de->d_name, "sentinel.log") == 0) {
            continue;
        }

        // Build absolute tracking path securely
        snprintf(path_buffer, sizeof(path_buffer), "%s/%s", base_path, de->d_name);

        if (stat(path_buffer, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                // Element is a directory: Initiate recursion to dive deeper into the host tree
                traverse_and_audit(path_buffer);
            } else if (S_ISREG(st.st_mode)) {
                // Element is a regular file: Audit contents
                calculate_file_sha256(path_buffer, hash_out);
                printf("[FILE] Path: %-35s | Size: %-6ld Bytes | SHA-256: %s\n", 
                       path_buffer, (long)st.st_size, hash_out);
            }
        }
    }
    closedir(dr);
}

int main() {
    printf("====================================================\n");
    printf("   LAUNCHING DEEP RECURSIVE ARCHITECTURE AUDIT     \n");
    printf("====================================================\n");
    traverse_and_audit("."); // Target current root and branch outwards
    return 0;
}
