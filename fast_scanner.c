#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#define TARGET_IP "127.0.0.1"
#define MAX_PORTS 100

void* scan_port(void* arg) {
    // Cast the argument to an int pointer and get the value
    int port = *((int*)arg);
    
    // CRITICAL: Free the memory allocated in main to prevent leaks
    free(arg); 

    int sock;
    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(TARGET_IP);
    server.sin_port = htons(port);

    // Set a small timeout so the scan doesn't hang on closed ports
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == 0) {
        printf("[!] Success: Port %d is OPEN\n", port);
    }

    close(sock);
    return NULL;
}

void shuffle(int *array, int n) {
    for (int i = n - 1; i > 0; i--) {
        int j = rand() % (i + 1);
        int temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}

int main() {
    pthread_t threads[MAX_PORTS];
    int ports[MAX_PORTS];

    srand(time(NULL));

    // Initialize the port array
    for (int i = 0; i < MAX_PORTS; i++) {
        ports[i] = i + 1;
    }

    // Randomize the order
    shuffle(ports, MAX_PORTS);

    printf("Starting scan on %s...\n", TARGET_IP);

    for (int i = 0; i < MAX_PORTS; i++) {
        // Use heap allocation for thread safety
        int *p = malloc(sizeof(int));
        if (p == NULL) {
            fprintf(stderr, "Failed to allocate memory\n");
            continue;
        }
        
        *p = ports[i];
        
        if (pthread_create(&threads[i], NULL, scan_port, p) != 0) {
            perror("Failed to create thread");
            free(p); // Cleanup if thread creation fails
        }
    }

    // Wait for all threads to complete
    for (int i = 0; i < MAX_PORTS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Scan complete.\n");
    return 0;
}
