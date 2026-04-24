#include <stdio.h>
#include <stdlib.h>

int main() {
    char ip[20];
    printf("--- SECURITY PING TOOL ---\n");
    printf("Enter Target IP (e.g., 192.168.1.1): ");
    scanf("%s", ip);

    char command[50];
    sprintf(command, "ping %s", ip);

    printf("\n[!] Initiating connection test to %s...\n", ip);
    system(command);

    return 0;
}
