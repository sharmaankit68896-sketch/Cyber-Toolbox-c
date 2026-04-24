#include <stdio.h>
#include <stdlib.h>

int main() {
    char ip[20];
    int port;

    printf("--- HERO PORT SCANNER v1.0 ---\n");
    printf("Target IP: ");
    scanf("%s", ip);
    printf("Port to scan (e.g., 80, 443, 22): ");
    scanf("%d", &port);

    char command[100];
    sprintf(command, "powershell -Command \"Test-NetConnection -ComputerName %s -Port %d\"", ip, port);

    printf("\n[!] Probing Port %d on %s...\n", port, ip);
    system(command);

    return 0;
}
