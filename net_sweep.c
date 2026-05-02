#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
    #define PLATFORM_SLEEP(ms) Sleep(ms)
#else
    #include <unistd.h>
    #define PLATFORM_SLEEP(ms) usleep(ms * 1000) 
#endif

int main() {
    char base_ip[] = "192.168.1"; // CHANGE THIS based on your 'hostname -I' result
    char command[100];

    printf("--- [Cyber-Toolbox] Network Sweep Initiative ---\n");
    printf("Targeting Range: %s.1 to %s.254\n", base_ip, base_ip);
    printf("Status: Initializing scan...\n");

    for (int i = 1; i <= 254; i++) {
        // Construct the ping command based on OS
        #ifdef _WIN32
            // Windows: -n 1 (1 packet), -w 100 (100ms timeout)
            sprintf(command, "ping -n 1 -w 100 %s.%d > nul", base_ip, i);
        #else
            // Linux: -c 1 (1 packet), -W 1 (1s timeout)
            sprintf(command, "ping -c 1 -W 1 %s.%d > /dev/null 2>&1", base_ip, i);
        #endif

        int result = system(command);

        if (result == 0) {
            printf("\n[+] Host Found: %s.%d", base_ip, i);
        } else {
            printf(".");
            fflush(stdout); // Forces the dot to print immediately
        }

        PLATFORM_SLEEP(10); // Small delay to prevent CPU spikes
    }

    printf("\n--- Sweep Complete ---\n");
    return 0;
}

    
        

