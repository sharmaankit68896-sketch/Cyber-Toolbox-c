#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUFFER_SIZE 1024

void grab_banner(const char *ip, int port) {
    int sock;
    struct sockaddr_in server;
    char buffer[BUFFER_SIZE];
    
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        return; // Silent failure to maintain speed during loop execution
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);

    // Set an aggressive connection timeout of 1 second so the sweep doesn't stall
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char*)&timeout, sizeof(timeout));
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof(timeout));

    // Attempt rapid connection
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) == 0) {
        // Read service banner immediately upon successful handshake
        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);

        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("\n🎯 [PORT %d OPEN] -> Banner Retrieved:\n%s\n", port, buffer);
        } else {
            printf("[*] Port %d is open, but did not return an application banner string.\n", port);
        }
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <Target IP> <Start Port> <End Port>\n", argv[0]);
        printf("Example: %s 127.0.0.1 20 100\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int start_port = atoi(argv[2]);
    int end_port = atoi(argv[3]);

    if (start_port > end_port || start_port < 1 || end_port > 65535) {
        printf("[X] Error: Invalid port range boundaries provided.\n");
        return 1;
    }

    printf("====================================================\n");
    printf("         MULTI-PORT BANNER RECONNAISSANCE LOOP      \n");
    printf("====================================================\n");
    printf("[*] Targeted Host: %s\n", target_ip);
    printf("[*] Sweeping Range: %d -> %d\n\n", start_port, end_port);

    for (int port = start_port; port <= end_port; port++) {
        grab_banner(target_ip, port);
    }

    printf("\n[*] Sweep sequence concluded.\n");
    return 0;
}
