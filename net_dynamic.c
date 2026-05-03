#include <stdio.h>
#include <stdlib.h>

#include <string.h>

int main() {
    char base_ip[] = "172.20.10."; // Update this to your gateway range
    
    for (int i = 1; i <= 10; i++) {
        // Calculate exact size needed
        int size = strlen(base_ip) + 5; 
        
        // Dynamic Allocation
        char *dynamic_command = (char *)malloc(size * sizeof(char));

        if (dynamic_command == NULL) {
            fprintf(stderr, "Memory allocation failed!\n");
            return 1;
        }

        sprintf(dynamic_command, "ping -c 1 %s%d", base_ip, i);
        printf("Executing: %s\n", dynamic_command);
        system(dynamic_command);

        // Professional Cleanup: Preventing the Memory Leak
        free(dynamic_command); 
    }

    return 0;
}
