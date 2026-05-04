#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

#define TARGET_IP "127.0.0.1"

void* scan_port(void* arg) {
    int port = *((int*)arg);
    int sock;
    struct sockaddr_in server;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return NULL;

    server.sin_family = AF_INET;
    server.sin_addr.s_addr = inet_addr(TARGET_IP);
    server.sin_port = htons(port);

    // Attempt connection
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == 0) {
        printf("[!] Success: Port %d is OPEN\n", port);
    }

    close(sock);
    return NULL;
}

int main() {
    pthread_t threads[100];
    int ports[100];

    printf("--- [Cyber-Toolbox] Multi-Threaded Audit (Target: %s) ---\n", TARGET_IP);

    // Launching 100 threads to scan ports 1-100 simultaneously
    for (int i = 0; i < 100; i++) {
        ports[i] = i + 1;
        pthread_create(&threads[i], NULL, scan_port, &ports[i]);
    }

    for (int i = 0; i < 100; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("Parallel Audit Complete.\n");
    return 0;
}
