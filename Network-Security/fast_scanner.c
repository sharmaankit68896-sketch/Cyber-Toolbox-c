#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <errno.h>
#include <string.h>

#define TARGET_IP "127.0.0.1"
#define MAX_PORTS 100

void* scan_port(void* arg) {
    int port = *((int*)arg);
    free(arg); 

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    // Set a 1-second timeout for the connection attempt
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));

    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(TARGET_IP);
    server.sin_port = htons(port);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == 0) {
        printf("[!] Success: Port %d is OPEN\n", port);
    } else {
        // Log the specific reason for failure (e.g., Connection refused)
        printf("Port %d: %s\n", port, strerror(errno));
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

    for (int i = 0; i < MAX_PORTS; i++) {
        ports[i] = i + 1;
    }

    shuffle(ports, MAX_PORTS);

    printf("Starting thread-safe scan on %s...\n", TARGET_IP);

    for (int i = 0; i < MAX_PORTS; i++) {
        int *p = malloc(sizeof(int));
        if (p == NULL) continue;
        
        *p = ports[i];
        if (pthread_create(&threads[i], NULL, scan_port, p) != 0) {
            free(p);
        }
    }

    for (int i = 0; i < MAX_PORTS; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Scan complete.\n");
    return 0;
}
