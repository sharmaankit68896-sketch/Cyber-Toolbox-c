#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main() {
    char base_ip[] = "10.255.207.192"; // Change this to match your router's IP range
    char command[50];

    printf("--- Starting Network Sweep on %s0/24 ---\n", base_ip);

    for (int i = 1; i <= 254; i++) {
        // Construct the command: ping -n 1 -w 100 10.255.207.192.i
        // -n 1: only 1 packet
        // -w 100: wait only 100ms (fast scan)
        sprintf(command, "ping -n 1 -w 100 %s%d > nul", base_ip, i);

        int result = system(command);

        if (result == 0) {
            printf("[+] Host Found: %s%d\n", base_ip, i);
        }
    }

    printf("--- Sweep Complete ---\n");
    return 0;
}
