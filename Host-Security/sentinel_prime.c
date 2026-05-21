#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <time.h>

#define BASELINE_FILE ".baseline.txt"
#define LOG_FILE "sentinel.log"

void log_incident(const char *message) {
    FILE *log = fopen(LOG_FILE, "a");
    if (log) {
        time_t now = time(NULL);
        char *time_str = ctime(&now);
        time_str[strlen(time_str) - 1] = '\0'; // Strip newline
        fprintf(log, "[%s] %s\n", time_str, message);
        fclose(log);
    }
}

void calculate_sha256(const char *path, char output[65]) {
    FILE *file = fopen(path, "rb");
    if (!file) {
        strcpy(output, "0000000000000000000000000000000000000000000000000000000000000000");
        return;
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned char buffer[4096];
    int bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) != 0) {
        SHA256_Update(&sha256, buffer, bytes_read);
    }

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);
    fclose(file);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        sprintf(output + (i * 2), "%02x", hash[i]);
    }
    output[64] = '\0';
}

void build_baseline(const char *base_path, FILE *baseline) {
    struct dirent *de;
    DIR *dr = opendir(base_path);
    struct stat st;
    char path_buffer[1024];
    char hash_out[65];

    if (!dr) return;

    while ((de = readdir(dr)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0 || 
            strcmp(de->d_name, BASELINE_FILE) == 0 || strcmp(de->d_name, LOG_FILE) == 0 ||
            strcmp(de->d_name, ".git") == 0) {
            continue;
        }

        snprintf(path_buffer, sizeof(path_buffer), "%s/%s", base_path, de->d_name);

        if (stat(path_buffer, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                build_baseline(path_buffer, baseline);
            } else if (S_ISREG(st.st_mode)) {
                calculate_sha256(path_buffer, hash_out);
                fprintf(baseline, "%s %ld %ld %s\n", path_buffer, (long)st.st_size, (long)st.st_mtime, hash_out);
                printf("[SNAPSHOT] Registered: %s\n", path_buffer);
            }
        }
    }
    closedir(dr);
}

void verify_integrity(const char *base_path) {
    struct dirent *de;
    DIR *dr = opendir(base_path);
    struct stat st;
    char path_buffer[1024];
    char current_hash[65];
    char line_buffer[2048];
    char alert_msg[512];

    if (!dr) return;

    while ((de = readdir(dr)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0 || 
            strcmp(de->d_name, BASELINE_FILE) == 0 || strcmp(de->d_name, LOG_FILE) == 0 ||
            strcmp(de->d_name, ".git") == 0) {
            continue;
        }

        snprintf(path_buffer, sizeof(path_buffer), "%s/%s", base_path, de->d_name);

        if (stat(path_buffer, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                verify_integrity(path_buffer);
            } else if (S_ISREG(st.st_mode)) {
                calculate_sha256(path_buffer, current_hash);

                FILE *baseline = fopen(BASELINE_FILE, "r");
                int found = 0;
                char b_path[1024], b_hash[65];
                long b_size, b_time;

                if (baseline) {
                    while (fgets(line_buffer, sizeof(line_buffer), baseline)) {
                        sscanf(line_buffer, "%s %ld %ld %s", b_path, &b_size, &b_time, b_hash);
                        if (strcmp(b_path, path_buffer) == 0) {
                            found = 1;
                            break;
                        }
                    }
                    fclose(baseline);
                }

                if (!found) {
                    snprintf(alert_msg, sizeof(alert_msg), "NEW_UNTRACKED_FILE_DETECTED: %s", path_buffer);
                    printf("[!] ALERT: Untracked artifact matching vector entry -> %s\n", path_buffer);
                    log_incident(alert_msg);
                } else {
                    int tampered = 0;
                    if (b_size != st.st_size) {
                        snprintf(alert_msg, sizeof(alert_msg), "SIZE_MISMATCH: %s (Expected: %ld, Got: %ld)", path_buffer, b_size, st.st_size);
                        log_incident(alert_msg);
                        tampered = 1;
                    }
                    if (b_time != st.st_mtime) {
                        snprintf(alert_msg, sizeof(alert_msg), "TIMESTAMP_MISMATCH: %s", path_buffer);
                        log_incident(alert_msg);
                        tampered = 1;
                    }
                    if (strcmp(b_hash, current_hash) != 0) {
                        snprintf(alert_msg, sizeof(alert_msg), "CRYPTOGRAPHIC_HASH_CORRUPTION: %s", path_buffer);
                        log_incident(alert_msg);
                        tampered = 1;
                    }

                    if (tampered) {
                        printf("[DANGER] File Compromised -> %s\n", path_buffer);
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
    FILE *baseline = fopen(BASELINE_FILE, "r");
    
    if (!baseline) {
        printf("[+] Initializing Unified Host Integrity Engine Baseline...\n");
        baseline = fopen(BASELINE_FILE, "w");
        if (!baseline) {
            perror("Baseline creation failed");
            return 1;
        }
        build_baseline(".", baseline);
        fclose(baseline);
        printf("[*] Baseline state preservation sequence complete.\n");
    } else {
        fclose(baseline);
        printf("--- [Executing Recursive Sentinel Multi-Factor Audit] ---\n");
        verify_integrity(".");
    }
    return 0;
}
