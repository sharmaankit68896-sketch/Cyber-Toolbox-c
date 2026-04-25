#include <stdio.h>
#include <stdlib.h>

void encrypt_decrypt(char *input_file, char *output_file, char key) {
    FILE *in = fopen(input_file, "rb");
    FILE *out = fopen(output_file, "wb");

    if (in == NULL || out == NULL) {
        printf("Error: Could not open files.\n");
        return;
    }
    char ch;
    while ((ch = fgetc(in)) != EOF) {
        // The XOR Magic
        fputc(ch ^ key, out);
    }
    fclose(in);
    fclose(out);
    printf("Operation successful. Check: %s\n", output_file);
}
int main() {
    char inputFile[100], outputFile[100];
    int userKey;

    printf("--- Cyber-Toolbox Encryptor ---\n");
    printf("Enter source file name: ");
    scanf("%s", inputFile);
    printf("Enter destination file name: ");
    scanf("%s", outputFile);
    printf("Enter a secret numeric key (1-255): ");
    scanf("%d", &userKey);

    encrypt_decrypt(inputFile, outputFile, (char)userKey);

    return 0;
}
