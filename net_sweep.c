#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h> // Essential for Sleep()

int main() {
    // Change "192.168.1." to match your actual gateway (use ipconfig to check)
    char base_ip[] = "192.168.1."; 
    char command[100];

    printf("--- [Cyber-Toolbox] Network Sweep Initiative ---\n");
    printf("Targeting Range: %s1 to %s254\n", base_ip, base_ip);
    printf("Status: Initializing stealth scan...\n\n");

    for (int i = 1; i <= 254; i++) {
        // Constructing the ping command
        // -n 1: Send only 1 packet
        // -w 100: Wait 100ms for response
        // > nul: Hide the raw ping output from the terminal
        sprintf(command, "ping -n 1 -w 100 %s%d > nul", base_ip, i);

        // Execute the command
        int result = system(command);
        
        if (result == 0) {
            printf("[+] ACTIVE HOST: %s%d\n", base_ip, i);
        } else {
            // Optional: print a dot to show progress for inactive IPs
            printf("."); 
            fflush(stdout);
        }
        
        // --- STEALTH IMPLEMENTATION ---
        // Sleep(50) pauses the program for 50 milliseconds.
        // This prevents your CPU and the network from being flooded.
        Sleep(50); 
    }

    printf("\n\n--- Sweep Complete ---\n");
    return 0;
}
