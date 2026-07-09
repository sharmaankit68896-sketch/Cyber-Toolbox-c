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
    
    // Create standard stream socket (TCP)
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[!] Socket allocation failed");
        return;
    }

    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = inet_addr(ip);

    printf("[*] Connecting to %s:%d...\n", ip, port);

    // Attempt network connection
    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        printf("[X] Connection failed on port %d. Port may be closed or filtered.\n", port);
        close(sock);
        return;
    }

    // Set a timeout of 3 seconds so the program doesn't hang forever if no banner is sent
    struct timeval tv;
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv));

    // Read the server greeting string
    memset(buffer, 0, BUFFER_SIZE);
    int bytes_received = recv(sock, buffer, BUFFER_SIZE - 1, 0);

    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        printf("\n🎯 [BANNER RETRIEVED FROM PORT %d]:\n", port);
        printf("%s\n", buffer);
    } else {
        printf("[!] Connected, but no banner was exposed within the timeout period.\n");
    }

    close(sock);
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Usage: %s <Target IP> <Target Port>\n", argv[0]);
        printf("Example: %s 192.168.1.1 22\n", argv[0]);
        return 1;
    }

    const char *target_ip = argv[1];
    int target_port = atoi(argv[2]);

    printf("====================================================\n");
    printf("        AUTOMATED RECONNAISSANCE BANNER GRABBER     \n");
    printf("====================================================\n");

    grab_banner(target_ip, target_port);

    return 0;
}

