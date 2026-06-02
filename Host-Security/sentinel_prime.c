#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <time.h>

#define BASELINE_FILE ".baseline.txt"
#define LOG_FILE "sentinel.log"
#define AUTH_STRING "SENTINEL_AUTH_TOKEN"

void log_incident(const char *message) {
    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str) - 1] = '\0';
        fprintf(log, "[%s] %s\n", time_str, message);
        fclose(log);
    }
}

// Computes HMAC-SHA256 of a memory buffer (used for key verification tokens)
void calculate_buffer_hmac(const char *data, const char *key, char output[65]) {
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, strlen(key), EVP_sha256(), NULL);
    HMAC_Update(ctx, (unsigned char*)data, strlen(data));

    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    HMAC_Final(ctx, hmac_result, &hmac_len);
    HMAC_CTX_free(ctx);

    for (unsigned int i = 0; i < hmac_len; i++) {
        sprintf(output + (i * 2), "%02x", hmac_result[i]);
    }
    output[64] = '\0';
}

// Computes HMAC-SHA256 of a file using a secret key
void calculate_file_hmac(const char *path, const char *key, char output[65]) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        strcpy(output, "0000000000000000000000000000000000000000000000000000000000000000");
        return;
    }

    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, strlen(key), EVP_sha256(), NULL);

    unsigned char buffer[4096];
    int bytes_read;
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        HMAC_Update(ctx, buffer, bytes_read);
    }

    unsigned char hmac_result[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    HMAC_Final(ctx, hmac_result, &hmac_len);
    HMAC_CTX_free(ctx);
    fclose(file);

    for (unsigned int i = 0; i < hmac_len; i++) {
        sprintf(output + (i * 2), "%02x", hmac_result[i]);
    }
    output[64] = '\0';
}

void build_baseline(const char *base_path, const char *key, FILE *baseline) {
    struct dirent *de;
    DIR *dr = opendir(base_path);
    struct stat st;
    char path_buffer[1024];
    char hmac_out[65];

    if (!dr) return;

    while ((de = readdir(dr)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0 || 
            strcmp(de->d_name, BASELINE_FILE) == 0 || strcmp(de->d_name, LOG_FILE) == 0 ||
            strcmp(de->d_name, ".git") == 0 || strcmp(de->d_name, "sentinel_prime") == 0) {
            continue;
        }

        snprintf(path_buffer, sizeof(path_buffer), "%s/%s", base_path, de->d_name);

        if (stat(path_buffer, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                build_baseline(path_buffer, key, baseline);
            } else if (S_ISREG(st.st_mode)) {
                calculate_file_hmac(path_buffer, key, hmac_out);
                fprintf(baseline, "%s %ld %s\n", path_buffer, (long)st.st_size, hmac_out);
                printf("[SNAPSHOT] Signed & Registered: %s\n", path_buffer);
            }
        }
    }
    closedir(dr);
}

void verify_integrity(const char *base_path, const char *key) {
    struct dirent *de;
    DIR *dr = opendir(base_path);
    struct stat st;
    char path_buffer[1024];
    char current_hmac[65];
    char line_buffer[2048];
    char alert_msg[512];

    if (!dr) return;

    while ((de = readdir(dr)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0 || 
            strcmp(de->d_name, BASELINE_FILE) == 0 || strcmp(de->d_name, LOG_FILE) == 0 ||
            strcmp(de->d_name, ".git") == 0 || strcmp(de->d_name, "sentinel_prime") == 0) {
            continue;
        }

        snprintf(path_buffer, sizeof(path_buffer), "%s/%s", base_path, de->d_name);

        if (stat(path_buffer, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                verify_integrity(path_buffer, key);
            } else if (S_ISREG(st.st_mode)) {
                calculate_file_hmac(path_buffer, key, current_hmac);

                FILE *baseline = fopen(BASELINE_FILE, "r");
                int found = 0;
                char b_path[1024], b_hmac[65];
                long b_size;

                if (baseline) {
                    // Skip the first line containing the authentication token block
                    if (fgets(line_buffer, sizeof(line_buffer), baseline)) {
                        while (fgets(line_buffer, sizeof(line_buffer), baseline)) {
                            if (sscanf(line_buffer, "%s %ld %s", b_path, &b_size, b_hmac) == 3) {
                                if (strcmp(b_path, path_buffer) == 0) {
                                    found = 1;
                                    break;
                                }
                            }
                        }
                    }
                    fclose(baseline);
                }

                if (!found) {
                    snprintf(alert_msg, sizeof(alert_msg), "UNTRACKED_FILE: %s", path_buffer);
                    printf("[!] ALERT: Untracked file detected -> %s\n", path_buffer);
                    log_incident(alert_msg);
                } else {
                    int tampered = 0;
                    if (b_size != st.st_size) {
                        snprintf(alert_msg, sizeof(alert_msg), "SIZE_MISMATCH: %s", path_buffer);
                        log_incident(alert_msg);
                        tampered = 1;
                    }
                    if (strcmp(b_hmac, current_hmac) != 0) {
                        snprintf(alert_msg, sizeof(alert_msg), "HMAC_MISMATCH/TAMPERED: %s", path_buffer);
                        log_incident(alert_msg);
                        tampered = 1;
                    }

                    if (tampered) {
                        printf("[DANGER] Integrity Breach Verified -> %s\n", path_buffer);
                    } else {
                        printf("[✓] Verified: %s\n", path_buffer);
                    }
                }
            }
        }
    }
    closedir(dr);
}

int main() {
    char key[128];
    printf("Enter Master Cryptographic Key: ");
    
    if (fgets(key, sizeof(key), stdin) == NULL) return 1;
    key[strcspn(key, "\r\n")] = 0; 

    if (strlen(key) < 4) {
        printf("Key too weak. Operational shutdown.\n");
        return 1;
    }

    FILE *baseline = fopen(BASELINE_FILE, "r");
    if (!baseline) {
        printf("[+] Initializing Cryptographically Signed Baseline State...\n");
        baseline = fopen(BASELINE_FILE, "w");
        if (!baseline) return 1;
        
        // Step 1: Create verification token block at the top of the file
        char auth_token[65];
        calculate_buffer_hmac(AUTH_STRING, key, auth_token);
        fprintf(baseline, "AUTH_TOKEN_BLOCK %s\n", auth_token);
        
        build_baseline(".", key, baseline);
        fclose(baseline);
        printf("[*] Signed baseline successfully locked.\n");
    } else {
        // Step 2: Validate the key prior to scanning files
        char stored_label[32], stored_token[65], computed_token[65];
        if (fscanf(baseline, "%31s %64s", stored_label, stored_token) != 2 || 
            strcmp(stored_label, "AUTH_TOKEN_BLOCK") != 0) {
            printf("[CRITICAL] Baseline structure corrupted or unsigned.\n");
            fclose(baseline);
            return 1;
        }
        fclose(baseline);

        calculate_buffer_hmac(AUTH_STRING, key, computed_token);
        if (strcmp(stored_token, computed_token) != 0) {
            printf("[!] ACCESS DENIED: Invalid Cryptographic Key. Audit Aborted.\n");
            log_incident("FAILURE: Unauthorized audit attempt with incorrect master key.");
            return 1;
        }

        printf("--- [Executing HMAC-SHA256 Multi-Factor Root Audit] ---\n");
        verify_integrity(".", key);
    }
    return 0;
}
