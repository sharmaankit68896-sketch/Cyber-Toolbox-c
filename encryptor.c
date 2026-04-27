#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Function to handle the XOR logic with a multi-character password
void process_file(char *input_path, char *output_path, char *key) {
    FILE *in = fopen(input_path, "rb");
    FILE *out = fopen(output_path, "wb");

    if (in == NULL || out == NULL) {
        printf("\n[!] ERROR: Could not access files. Check names and permissions.\n");
        return;
    }

    int key_len = strlen(key);
    int i = 0;
    int ch;

    // XOR every byte of the file with the corresponding byte of the key
    while ((ch = fgetc(in)) != EOF) {
        fputc(ch ^ key[i % key_len], out);
        i++;
    }

    fclose(in);
    fclose(out);
    printf("\n[+] SUCCESS: Processed %d bytes.\n[+] File saved as: %s\n", i, output_path);
}

int main() {
    char input_file[100], output_file[100], password[100];

    printf("--- Cyber-Toolbox Professional Encryptor ---\n");
    
    printf("Enter Source File (e.g., secret.txt): ");
    scanf("%s", input_file);
    
    printf("Enter Destination File (e.g., locked.bin): ");
    scanf("%s", output_file);
    
    printf("Enter Secret Password: ");
    scanf("%s", password);

    if (strlen(password) < 4) {
        printf("[!] WARNING: Short passwords are easy to crack. Use 8+ characters.\n");
    }

    process_file(input_file, output_file, password);

    return 0;
}

   

   
