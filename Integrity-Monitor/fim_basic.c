#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Function to calculate a basic "checksum" for integrity
long calculate_checksum(char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return -1;

    long checksum = 0;
    int c;
    while ((c = fgetc(f)) != EOF) {
        checksum += c;
    }
    fclose(f);
    return checksum;
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <file_to_monitor>\n", argv[0]);
        return 1;
    }

    char *target = argv[1];
    long original_hash = calculate_checksum(target);

    if (original_hash == -1) {
        printf("Error: Could not read file %s\n", target);
        return 1;
    }

    printf("[+] Monitoring: %s\n", target);
    printf("[+] Original Checksum: %ld\n", original_hash);
    printf("Waiting for changes... (Ctrl+C to stop)\n");

    while (1) {
        sleep(5); // Check every 5 seconds
        long current_hash = calculate_checksum(target);

        if (current_hash != original_hash) {
            printf("\n[!] ALERT: Integrity Violation Detected in %s!\n", target);
            printf("[!] New Checksum: %ld (Original: %ld)\n", current_hash, original_hash);
            original_hash = current_hash; // Reset to new state after alert
        }
    }

    return 0;
}

