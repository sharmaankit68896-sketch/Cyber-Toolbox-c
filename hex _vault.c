#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void encrypt_to_hex(char *input_path, char *output_path, char *password) {
    FILE *in = fopen(input_path, "rb");
    FILE *out = fopen(output_path, "w"); // Hex is stored as text

    if (!in || !out) {
        printf("[!] Critical Error: File access denied.\n");
        return;
    }

    int key_len = strlen(password);
    int i = 0;
    int ch;

    printf("[*] Encrypting stream...");

    while ((ch = fgetc(in)) != EOF) {
        // XOR Operation
        char scrambled = ch ^ password[i % key_len];
        
        // Write as 2-digit Hexadecimal
        fprintf(out, "%02x", (unsigned char)scrambled);
        i++;
    }

    fclose(in);
    fclose(out);
    printf("\n[+]\n Success! Vault locked: %s\n", output_path);
}

int main() {
    char source[100], destination[100], pass[100];

    printf("--- [Cyber-Toolbox] Hex-Vault Engine ---\n");
    printf("Enter source file: ");
    scanf("%s", source);
    printf("Enter destination (.txt or .hex): ");
    scanf("%s", destination);
    printf("Enter master password: ");
    scanf("%s", pass);

    encrypt_to_hex(source, destination, pass);

    return 0;
}
