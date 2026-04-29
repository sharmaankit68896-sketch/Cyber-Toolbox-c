#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void decrypt_from_hex(char *input_path, char *output_path, char *password) {
    FILE *in = fopen(input_path, "r");   // Reading the hex text
    FILE *out = fopen(output_path, "wb"); // Writing the original file/binary

    if (!in || !out) {
        printf("[!] Critical Error: Could not access files.\n");
        return;
    }

    int key_len = strlen(password);
    int i = 0;
    unsigned int hex_val;

    printf("[*] Decrypting stream...");

    // fscanf with %02x reads two hex characters and converts them to an integer
    while (fscanf(in, "%02x", &hex_val) != EOF) {
        // XOR the hex value with the password to get the original character
        char original = (char)hex_val ^ password[i % key_len];
        
        fputc(original, out);
        i++;
    }

    fclose(in);
    fclose(out);
    printf("\n[+]\n Success! Vault unlocked: %s\n", output_path);
}

int main() {
    char source[100], destination[100], pass[100];

    printf("--- [Cyber-Toolbox] Hex-Vault Decoder ---\n");
    printf("Enter encrypted file: ");
    scanf("%s", source);
    printf("Enter destination (original file name): ");
    scanf("%s", destination);
    printf("Enter master password: ");
    scanf("%s", pass);

    decrypt_from_hex(source, destination, pass);

    return 0;
}
